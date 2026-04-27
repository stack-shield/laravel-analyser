<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class AppKeyCheck implements Check
{
    public function id(): string
    {
        return 'SS010';
    }

    public function name(): string
    {
        return 'APP_KEY Missing or Weak';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
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
        // Check if APP_KEY is committed in .env
        $envFiles = $ctx->envFiles();

        foreach ($envFiles as $envFile) {
            if ($envFile === '.env.example') {
                continue;
            }

            $env = $ctx->env($envFile);
            $appKey = $env['APP_KEY'] ?? '';

            if ($appKey === '') {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "APP_KEY is empty in {$envFile}. Without an application key, encrypted data and sessions are insecure.",
                    file: $envFile,
                    line: $this->findLine($ctx, $envFile, 'APP_KEY'),
                    symbol: 'APP_KEY',
                    snippet: 'APP_KEY=',
                    remediation: 'Run `php artisan key:generate` to set a secure APP_KEY.',
                );

                continue;
            }

            // Check if it's a base64 key (Laravel default format)
            $keyValue = $appKey;
            if (str_starts_with($keyValue, 'base64:')) {
                $keyValue = base64_decode(substr($keyValue, 7));
            }

            if (strlen($keyValue) < 16) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "APP_KEY in {$envFile} is too short (".strlen($keyValue)." bytes). Laravel requires at least a 16-byte key.",
                    file: $envFile,
                    line: $this->findLine($ctx, $envFile, 'APP_KEY'),
                    symbol: 'APP_KEY',
                    remediation: 'Run `php artisan key:generate` to set a secure APP_KEY.',
                );
            }
        }

        // Check if .env is tracked in git (APP_KEY committed)
        if ($ctx->fileExists('.gitignore')) {
            $gitignore = $ctx->fileContents('.gitignore');
            $envIgnored = false;
            foreach (explode("\n", $gitignore) as $line) {
                $line = trim($line);
                if ($line === '.env' || $line === '/.env') {
                    $envIgnored = true;
                    break;
                }
            }

            if (! $envIgnored && $ctx->fileExists('.env')) {
                $env = $ctx->env('.env');
                if (! empty($env['APP_KEY'] ?? '')) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: Severity::Critical,
                        category: $this->category(),
                        message: '.env file is not in .gitignore. APP_KEY and other secrets may be committed to version control.',
                        file: '.gitignore',
                        symbol: 'APP_KEY',
                        remediation: 'Add `.env` to your .gitignore file and rotate your APP_KEY.',
                    );
                }
            }
        }
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
