<?php

namespace StackShield\Analyser\Checks\Routes;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class WildcardRouteCheck implements Check
{
    public function id(): string
    {
        return 'SS052';
    }

    public function name(): string
    {
        return 'Overly Broad Wildcard Routes';
    }

    public function severity(): Severity
    {
        return Severity::Low;
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
        $routeFiles = ['routes/web.php', 'routes/api.php'];

        foreach ($routeFiles as $file) {
            $contents = $ctx->fileContents($file);
            if ($contents === null) {
                continue;
            }

            $lines = explode("\n", $contents);

            foreach ($lines as $index => $line) {
                $trimmed = ltrim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*') || str_starts_with($trimmed, '/*')) {
                    continue;
                }

                $lineNum = $index + 1;

                // Detect Route::any()
                if (preg_match('/Route::any\s*\(/', $line)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: 'Route::any() accepts all HTTP methods. This broadens the attack surface by allowing unintended methods (e.g., DELETE, PUT) on the endpoint.',
                        file: $file,
                        line: $lineNum,
                        symbol: 'Route::any',
                        snippet: trim($line),
                        remediation: 'Replace Route::any() with a specific HTTP method: Route::get(), Route::post(), etc.',
                    );
                }

                // Detect catch-all parameters like {path?}, {any}, {any?}
                if (preg_match('/Route::(get|post|put|delete|patch|any|match)\s*\(/', $line)
                    && preg_match('/\{(path|any|all|catchall)\??\}/', $line, $matches)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: "Catch-all route parameter '{{$matches[1]}}' detected. Overly broad route parameters can be abused to access unintended application paths.",
                        file: $file,
                        line: $lineNum,
                        symbol: 'Route',
                        snippet: trim($line),
                        remediation: 'Use specific route parameters with constraints: Route::get(\'/page/{slug}\', ...)->where(\'slug\', \'[a-z-]+\');',
                    );
                }

                // Detect Route::match with many methods
                if (preg_match('/Route::match\s*\(\s*\[.*\]/', $line)) {
                    // Count methods in the match array
                    if (preg_match_all('/(get|post|put|delete|patch|options|head)/i', $line, $methodMatches)) {
                        if (count($methodMatches[0]) >= 4) {
                            yield new Finding(
                                checkId: $this->id(),
                                checkName: $this->name(),
                                checkVersion: $this->version(),
                                severity: $this->severity(),
                                category: $this->category(),
                                message: 'Route::match() with '.count($methodMatches[0]).' HTTP methods is nearly equivalent to Route::any(). This broadens the attack surface unnecessarily.',
                                file: $file,
                                line: $lineNum,
                                symbol: 'Route::match',
                                snippet: trim($line),
                                remediation: 'Reduce the accepted HTTP methods to only those actually needed by the endpoint.',
                            );
                        }
                    }
                }
            }
        }
    }
}
