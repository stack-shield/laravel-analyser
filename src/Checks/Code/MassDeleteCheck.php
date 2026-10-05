<?php

namespace StackShield\Analyser\Checks\Code;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;
use StackShield\Analyser\Routes\RouteCollector;

class MassDeleteCheck implements Check
{
    private const DANGEROUS_PATTERNS = [
        '/\b\w+::truncate\s*\(\s*\)/' => 'Model::truncate() will delete all rows from the table without any conditions',
        '/DB::table\s*\([^)]+\)\s*->\s*delete\s*\(\s*\)/' => 'DB::table()->delete() without a where clause will delete all rows from the table',
        '/\b\w+::query\s*\(\s*\)\s*->\s*delete\s*\(\s*\)/' => 'Model::query()->delete() without constraints will delete all records',
    ];

    public function id(): string
    {
        return 'SS054';
    }

    public function name(): string
    {
        return 'Unconstrained Mass Delete Operations';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
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
     * Deleting every row is routine in console commands, jobs and upgrade
     * scripts. It is a vulnerability when a request can trigger it: the
     * delete sits in a controller action that a route exposes without auth.
     */
    public function run(Context $ctx): iterable
    {
        $exposed = [];
        foreach (RouteCollector::routes($ctx) as $route) {
            if ($route->controller !== null && ! $route->localOnly && ! RouteCollector::requiresAuth($ctx, $route)) {
                $exposed[strtolower($route->controller.'@'.$route->action)] = $route;
            }
        }
        if ($exposed === []) {
            return;
        }

        $finder = new NodeFinder;
        foreach ($ctx->phpFiles('app/Http/Controllers') as $file) {
            $stmts = $ctx->ast($file);
            $lines = explode("\n", $ctx->fileContents($file) ?? '');

            foreach ($finder->findInstanceOf($stmts, Node\Stmt\Class_::class) as $class) {
                $className = $class->namespacedName?->toString() ?? $class->name?->toString();

                foreach ($class->getMethods() as $method) {
                    $route = $exposed[strtolower($className.'@'.$method->name->toString())] ?? null;
                    if ($route === null) {
                        continue;
                    }

                    for ($line = $method->getStartLine(); $line <= $method->getEndLine(); $line++) {
                        foreach (self::DANGEROUS_PATTERNS as $pattern => $description) {
                            if (! preg_match($pattern, $lines[$line - 1] ?? '')) {
                                continue;
                            }

                            yield new Finding(
                                checkId: $this->id(),
                                checkName: $this->name(),
                                checkVersion: $this->version(),
                                severity: Severity::High,
                                category: $this->category(),
                                message: "{$description}, in an action anyone can reach without logging in (".implode('|', $route->methods)." /{$route->uri}).",
                                file: $file,
                                line: $line,
                                symbol: $method->name->toString(),
                                snippet: trim($lines[$line - 1]),
                                remediation: 'Put the route behind auth and authorization, and add explicit where() constraints before delete().',
                            );

                            break;
                        }
                    }
                }
            }
        }
    }
}
