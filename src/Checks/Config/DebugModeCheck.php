<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class DebugModeCheck implements Check
{
    public function id(): string
    {
        return 'SS012';
    }

    public function name(): string
    {
        return 'Debug Mode in Production';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $productionEnvFiles = ['.env.production', '.env.staging'];

        foreach ($productionEnvFiles as $envFile) {
            $env = $ctx->env($envFile);
            if (empty($env)) {
                continue;
            }

            $debug = $env['APP_DEBUG'] ?? null;
            if ($debug !== null && $this->isTrue($debug)) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "APP_DEBUG is set to true in {$envFile}. This exposes detailed error pages, stack traces, and environment variables in production.",
                    file: $envFile,
                    line: $this->findLine($ctx, $envFile, 'APP_DEBUG'),
                    symbol: 'APP_DEBUG',
                    snippet: "APP_DEBUG={$debug}",
                    remediation: "Set APP_DEBUG=false in {$envFile}.",
                );
            }
        }

        // Also check the main .env if it looks like a production env
        $mainEnv = $ctx->env('.env');
        if (! empty($mainEnv)) {
            $appEnv = $mainEnv['APP_ENV'] ?? null;
            $debug = $mainEnv['APP_DEBUG'] ?? null;

            if ($appEnv === 'production' && $debug !== null && $this->isTrue($debug)) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: 'APP_DEBUG is set to true in .env while APP_ENV=production. This exposes detailed error pages and stack traces.',
                    file: '.env',
                    line: $this->findLine($ctx, '.env', 'APP_DEBUG'),
                    symbol: 'APP_DEBUG',
                    snippet: "APP_DEBUG={$debug}",
                    remediation: 'Set APP_DEBUG=false in .env.',
                );
            }
        }
    }

    private function isTrue(string $value): bool
    {
        return in_array(strtolower($value), ['true', '1', 'yes', 'on'], true);
    }

    private function findLine(Context $ctx, string $file, string $key): int
    {
        $contents = $ctx->fileContents($file);
        if ($contents === null) {
            return 0;
        }

        $lines = explode("\n", $contents);
        foreach ($lines as $i => $line) {
            if (str_starts_with(trim($line), $key.'=')) {
                return $i + 1;
            }
        }

        return 0;
    }
}
