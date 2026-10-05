<?php

namespace StackShield\Analyser\Checks\Code;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class MassAssignmentCheck implements Check
{
    /**
     * create($request->all()), ->update(request()->except([...])),
     * forceFill(Request::input()) and similar: a whole request array, not a
     * single field or a validated subset.
     */
    private const RAW_REQUEST_CALL = '/(?<receiver>\$this->|->|::)(?<method>create|fill|update|forceFill|forceCreate|firstOrCreate|updateOrCreate)\(\s*(?<lead>[^()]*,\s*)?(?:\$request->|request\(\)->|Request::)(?:(?:all|input|post)\(\s*\)|except\()/';

    public function id(): string
    {
        return 'SS001';
    }

    public function name(): string
    {
        return 'Mass Assignment';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function category(): Category
    {
        return Category::Code;
    }

    public function version(): int
    {
        return 2;
    }

    /**
     * Eloquent guards every attribute by default, so a model without $fillable
     * or $guarded is safe: mass assignment throws. The vulnerability is
     * unvalidated request data reaching a mass-assignment call when guarding is
     * off ($guarded = [] or a global Model::unguard()), or reaching forceFill()
     * and forceCreate(), which ignore guarding altogether.
     */
    public function run(Context $ctx): iterable
    {
        $unguarded = $this->unguardedModels($ctx);
        $globallyUnguarded = $this->globallyUnguarded($ctx);

        foreach ($ctx->phpFiles('app') as $file) {
            $contents = $ctx->fileContents($file) ?? '';

            if (! preg_match_all(self::RAW_REQUEST_CALL, $contents, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                continue;
            }

            foreach ($matches as $match) {
                $method = $match['method'][0];

                // $this->create($request->all()) is the controller's own helper (the
                // classic RegisterController), and only *OrCreate takes the data as a
                // second argument; anything else with a leading argument is not Eloquent.
                if ($match['receiver'][0] === '$this->'
                    || (($match['lead'][0] ?? '') !== '' && ! in_array($method, ['firstOrCreate', 'updateOrCreate'], true))) {
                    continue;
                }
                $bypassesGuarding = in_array($method, ['forceFill', 'forceCreate'], true);

                if (! $bypassesGuarding && ! $globallyUnguarded && $unguarded === []) {
                    continue;
                }

                $line = substr_count(substr($contents, 0, $match[0][1]), "\n") + 1;
                $why = $bypassesGuarding
                    ? "{$method}() ignores \$fillable and \$guarded"
                    : ($globallyUnguarded
                        ? 'Model::unguard() turns guarding off for every model'
                        : 'models with $guarded = [] ('.implode(', ', array_slice($unguarded, 0, 3)).(count($unguarded) > 3 ? ', ...' : '').') accept every attribute');

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "Unvalidated request data is passed to {$method}(), and {$why}. A user can set any column, such as is_admin or user_id.",
                    file: $file,
                    line: $line,
                    symbol: $method,
                    snippet: trim(strtok(substr($contents, $match[0][1]), "\n")),
                    remediation: "Pass \$request->validated() or \$request->only([...]) instead of \$request->all(), and declare \$fillable on the model.",
                );
            }
        }
    }

    /** @return string[] Short names of models declaring $guarded = []. */
    private function unguardedModels(Context $ctx): array
    {
        $models = [];

        foreach ($ctx->phpFiles('app') as $file) {
            $contents = $ctx->fileContents($file) ?? '';
            if (preg_match('/\$guarded\s*=\s*(?:\[\s*\]|array\(\s*\))\s*;/', $contents)
                && preg_match('/class\s+(\w+)/', $contents, $class)) {
                $models[] = $class[1];
            }
        }

        return $models;
    }

    private function globallyUnguarded(Context $ctx): bool
    {
        foreach ($ctx->phpFiles('app/Providers') as $file) {
            if (preg_match('/Model::unguard\(\s*\)/', $ctx->fileContents($file) ?? '')) {
                return true;
            }
        }

        return false;
    }
}
