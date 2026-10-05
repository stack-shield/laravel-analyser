<?php

namespace StackShield\Analyser\Checks\Routes;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class ApiRateLimitCheck implements Check
{
    public function id(): string
    {
        return 'SS050';
    }

    public function name(): string
    {
        return 'API Routes Missing Rate Limiting';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function category(): Category
    {
        return Category::Routes;
    }

    public function version(): int
    {
        return 2;
    }

    /**
     * Throttling is usually applied to the whole api group, not per route: in
     * the group definition (app/Http/Kernel.php on Laravel 10, bootstrap/app.php
     * with throttleApi() or a custom group on 11+), or by the provider that
     * loads the route file. One unthrottled API is one finding, however many
     * routes it has.
     */
    public function run(Context $ctx): iterable
    {
        $file = 'routes/api.php';
        $contents = $ctx->fileContents($file);

        if ($contents === null) {
            return;
        }

        $routeCount = preg_match_all('/Route::(get|post|put|delete|patch|any|match|resource|apiResource)\s*\(/i', $contents);
        if ($routeCount === 0) {
            return;
        }

        foreach ($this->throttleSources($ctx) as $source) {
            if (preg_match('/throttle/i', $ctx->fileContents($source) ?? '')) {
                return;
            }
        }

        yield new Finding(
            checkId: $this->id(),
            checkName: $this->name(),
            checkVersion: $this->version(),
            severity: $this->severity(),
            category: $this->category(),
            message: "No rate limiting found for the {$routeCount} routes in routes/api.php: neither the routes nor the api middleware group apply throttle middleware. Unthrottled API endpoints are open to brute-force and denial-of-service attacks.",
            file: $file,
            symbol: 'api',
            remediation: "Throttle the api group: \$middleware->throttleApi() in bootstrap/app.php (Laravel 11+), 'throttle:api' in the api group of app/Http/Kernel.php (Laravel 10), or Route::middleware('throttle:api')->group(...) in routes/api.php.",
        );
    }

    /** @return string[] Files where the api group or its routes may be throttled. */
    private function throttleSources(Context $ctx): array
    {
        $sources = ['routes/api.php', 'app/Http/Kernel.php', 'bootstrap/app.php'];

        foreach ($ctx->phpFiles('app/Providers') as $provider) {
            if (str_contains($ctx->fileContents($provider) ?? '', 'api.php')) {
                $sources[] = $provider;
            }
        }

        return $sources;
    }
}
