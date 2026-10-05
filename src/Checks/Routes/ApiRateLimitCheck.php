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
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $file = 'routes/api.php';
        $contents = $ctx->fileContents($file);

        if ($contents === null) {
            return;
        }

        // If the file contains 'throttle' anywhere (group-level or per-route), it's likely protected
        if (str_contains($contents, 'throttle')) {
            return;
        }

        // Check for route definitions without throttle middleware
        $lines = explode("\n", $contents);
        $routePattern = '/Route::(get|post|put|delete|patch|any|match)\s*\(/i';

        $foundRoutes = false;
        foreach ($lines as $index => $line) {
            if (preg_match($routePattern, $line)) {
                $foundRoutes = true;
                $lineNum = $index + 1;

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: 'API route defined without throttle middleware. Unthrottled API endpoints are vulnerable to brute-force and denial-of-service attacks.',
                    file: $file,
                    line: $lineNum,
                    symbol: 'Route',
                    snippet: trim($line),
                    remediation: "Apply rate limiting via middleware: Route::middleware('throttle:api')->group(...) or add ->middleware('throttle:60,1') to individual routes.",
                );
            }
        }

        if (! $foundRoutes) {
            return;
        }
    }
}
