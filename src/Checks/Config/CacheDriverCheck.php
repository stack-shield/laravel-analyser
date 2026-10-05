<?php

namespace StackShield\Analyser\Checks\Config;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class CacheDriverCheck implements Check
{
    public function id(): string
    {
        return 'SS048';
    }

    public function name(): string
    {
        return 'File Cache Driver in Production';
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
        $productionEnvFiles = ['.env.production', '.env.staging'];

        foreach ($productionEnvFiles as $envFile) {
            $env = $ctx->env($envFile);
            if (empty($env)) {
                continue;
            }

            yield from $this->checkEnv($ctx, $env, $envFile);
        }

        // Also check the main .env if it looks like a production env
        $mainEnv = $ctx->env('.env');
        if (! empty($mainEnv)) {
            $appEnv = $mainEnv['APP_ENV'] ?? null;
            if ($appEnv === 'production') {
                yield from $this->checkEnv($ctx, $mainEnv, '.env');
            }
        }
    }

    private function checkEnv(Context $ctx, array $env, string $envFile): iterable
    {
        // Laravel 10 and earlier use CACHE_DRIVER, Laravel 11+ uses CACHE_STORE
        $cacheDriver = $env['CACHE_DRIVER'] ?? null;
        $cacheStore = $env['CACHE_STORE'] ?? null;

        if ($cacheDriver === 'file') {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: "CACHE_DRIVER is set to 'file' in {$envFile}. File-based caching is slow and can cause race conditions at scale in production.",
                file: $envFile,
                line: $this->findLine($ctx, $envFile, 'CACHE_DRIVER'),
                symbol: 'CACHE_DRIVER',
                snippet: "CACHE_DRIVER={$cacheDriver}",
                remediation: "Set CACHE_DRIVER to 'redis' or 'memcached' in {$envFile} for better performance and reliability.",
            );
        }

        if ($cacheStore === 'file') {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: "CACHE_STORE is set to 'file' in {$envFile}. File-based caching is slow and can cause race conditions at scale in production.",
                file: $envFile,
                line: $this->findLine($ctx, $envFile, 'CACHE_STORE'),
                symbol: 'CACHE_STORE',
                snippet: "CACHE_STORE={$cacheStore}",
                remediation: "Set CACHE_STORE to 'redis' or 'memcached' in {$envFile} for better performance and reliability.",
            );
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
            if (str_starts_with(trim($line), $key . '=')) {
                return $i + 1;
            }
        }

        return 0;
    }
}
