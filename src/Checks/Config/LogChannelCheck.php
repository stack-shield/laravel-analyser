<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class LogChannelCheck implements Check
{
    public function id(): string
    {
        return 'SS014';
    }

    public function name(): string
    {
        return 'Debug Log Level in Production';
    }

    public function severity(): Severity
    {
        return Severity::Low;
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
        foreach ($ctx->envFiles() as $envFile) {
            if ($envFile === '.env.example') {
                continue;
            }

            $env = $ctx->env($envFile);
            $appEnv = $env['APP_ENV'] ?? null;

            if ($envFile === '.env' && $appEnv !== 'production') {
                continue;
            }

            $logLevel = $env['LOG_LEVEL'] ?? null;
            if ($logLevel !== null && in_array(strtolower($logLevel), ['debug'], true)) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "LOG_LEVEL is set to 'debug' in {$envFile}. This generates excessive logs and may expose sensitive data.",
                    file: $envFile,
                    symbol: 'LOG_LEVEL',
                    remediation: "Set LOG_LEVEL=warning or LOG_LEVEL=error in {$envFile} for production.",
                );
            }
        }
    }
}
