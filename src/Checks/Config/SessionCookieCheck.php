<?php

namespace StackShield\Analyser\Checks\Config;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class SessionCookieCheck implements Check
{
    public function id(): string
    {
        return 'SS015';
    }

    public function name(): string
    {
        return 'Session Cookie Security';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
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
        // Check env files for session cookie settings
        foreach ($ctx->envFiles() as $envFile) {
            if ($envFile === '.env.example') {
                continue;
            }

            $env = $ctx->env($envFile);
            $appEnv = $env['APP_ENV'] ?? null;

            // Only flag production-like envs
            if ($envFile === '.env' && $appEnv !== 'production' && $appEnv !== 'staging') {
                continue;
            }

            $secureCookie = $env['SESSION_SECURE_COOKIE'] ?? null;
            if ($secureCookie !== null && $this->isFalse($secureCookie)) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "SESSION_SECURE_COOKIE is set to false in {$envFile}. Session cookies will be sent over unencrypted HTTP connections.",
                    file: $envFile,
                    line: $this->findLine($ctx, $envFile, 'SESSION_SECURE_COOKIE'),
                    symbol: 'SESSION_SECURE_COOKIE',
                    snippet: "SESSION_SECURE_COOKIE={$secureCookie}",
                    remediation: "Set SESSION_SECURE_COOKIE=true in {$envFile} to ensure cookies are only sent over HTTPS.",
                );
            }

            $sameSite = $env['SESSION_SAME_SITE'] ?? null;
            if ($sameSite !== null && strtolower($sameSite) === 'none') {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "SESSION_SAME_SITE is set to 'none' in {$envFile}. This disables SameSite protection against CSRF attacks.",
                    file: $envFile,
                    line: $this->findLine($ctx, $envFile, 'SESSION_SAME_SITE'),
                    symbol: 'SESSION_SAME_SITE',
                    snippet: "SESSION_SAME_SITE={$sameSite}",
                    remediation: "Set SESSION_SAME_SITE=lax in {$envFile} (or 'strict' if cross-site requests aren't needed).",
                );
            }
        }

        // Check session.php config file if it exists
        $sessionConfig = $ctx->fileContents('config/session.php');
        if ($sessionConfig !== null) {
            if (preg_match("/['\"]secure['\"]\\s*=>\\s*false/", $sessionConfig)) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "Session cookie 'secure' is hardcoded to false in config/session.php. Use env('SESSION_SECURE_COOKIE') to allow per-environment configuration.",
                    file: 'config/session.php',
                    symbol: 'session.secure',
                    remediation: "Change 'secure' to use env('SESSION_SECURE_COOKIE', true) in config/session.php.",
                );
            }
        }
    }

    private function isFalse(string $value): bool
    {
        return in_array(strtolower($value), ['false', '0', 'no', 'off'], true);
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
