<?php

namespace StackShield\Analyser\Checks\Routes;

use StackShield\Analyser\Checks\Advisory;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class DebugRoutesCheck implements Advisory, Check
{
    /**
     * Whole-route debug endpoints. Features named "test" (send a test email,
     * test a webhook, {rule}/test) are not debug routes, so the URI has to be
     * a debug endpoint itself.
     */
    private function debugRoute(string $line): ?string
    {
        if (str_contains($line, 'phpinfo(')) {
            return 'The route calls phpinfo(), which exposes the full PHP configuration and environment variables';
        }
        if (! preg_match('/Route::\w+\(\s*[\'"]([^\'"]*)[\'"]/', $line, $m)) {
            return null;
        }
        $segments = explode('/', strtolower(trim($m[1], '/')));
        if (in_array('phpinfo', $segments, true)) {
            return 'A phpinfo route exposes the full PHP configuration and environment variables';
        }
        if (in_array($segments[0], ['debug', '_debug', 'test', 'tests', 'dump'], true)) {
            return "The '{$m[1]}' route looks like a leftover debug or test endpoint that may expose application internals";
        }

        return null;
    }

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
        return 2;
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

                $description = $this->debugRoute($line);
                if ($description === null) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "Debug route detected. {$description}.",
                    file: $file,
                    line: $index + 1,
                    symbol: 'Route',
                    snippet: trim($line),
                    remediation: 'Remove debug and test routes before deploying to production, or wrap them in an environment check: if (app()->environment(\'local\')) { ... }',
                );
            }
        }
    }
}
