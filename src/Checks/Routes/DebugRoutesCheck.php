<?php

namespace StackShield\Analyser\Checks\Routes;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class DebugRoutesCheck implements Check
{
    private const DEBUG_PATTERNS = [
        '/test' => 'Test route that may expose application internals',
        '/debug' => 'Debug route that may leak sensitive information',
        '/phpinfo' => 'phpinfo() route exposes full PHP configuration and environment variables',
        '/info' => 'Info route that may expose application details',
        'telescope' => 'Laravel Telescope route should not be accessible in production',
    ];

    public function id(): string
    {
        return 'SS051';
    }

    public function name(): string
    {
        return 'Debug/Test Routes in Production';
    }

    public function severity(): Severity
    {
        return Severity::High;
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
                // Skip comments
                $trimmed = ltrim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*') || str_starts_with($trimmed, '/*')) {
                    continue;
                }

                foreach (self::DEBUG_PATTERNS as $pattern => $description) {
                    if (stripos($line, $pattern) !== false && preg_match('/Route::/', $line)) {
                        $lineNum = $index + 1;

                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $this->severity(),
                            category: $this->category(),
                            message: "Debug/test route detected containing '{$pattern}'. {$description}.",
                            file: $file,
                            line: $lineNum,
                            symbol: 'Route',
                            snippet: trim($line),
                            remediation: 'Remove debug and test routes before deploying to production, or wrap them in an environment check: if (app()->environment(\'local\')) { ... }',
                        );

                        break; // One finding per line
                    }
                }
            }
        }
    }
}
