<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class ForceHttpsCheck implements Check
{
    public function id(): string
    {
        return 'SS049';
    }

    public function name(): string
    {
        return 'HTTPS Not Enforced';
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
        $productionEnvFiles = ['.env.production', '.env.staging'];

        foreach ($productionEnvFiles as $envFile) {
            $env = $ctx->env($envFile);
            if (empty($env)) {
                continue;
            }

            yield from $this->checkAppUrl($ctx, $env, $envFile);
        }

        // Also check the main .env if it looks like a production env
        $mainEnv = $ctx->env('.env');
        if (! empty($mainEnv)) {
            $appEnv = $mainEnv['APP_ENV'] ?? null;
            if ($appEnv === 'production') {
                yield from $this->checkAppUrl($ctx, $mainEnv, '.env');
            }
        }

        // Check if URL::forceScheme('https') is present in AppServiceProvider
        $providerFile = 'app/Providers/AppServiceProvider.php';
        $providerContents = $ctx->fileContents($providerFile);

        if ($providerContents !== null) {
            $hasForceHttps = str_contains($providerContents, "forceScheme('https')")
                || str_contains($providerContents, 'forceScheme("https")');

            if (! $hasForceHttps) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "URL::forceScheme('https') is not present in AppServiceProvider. Generated URLs may use HTTP instead of HTTPS.",
                    file: $providerFile,
                    symbol: 'URL::forceScheme',
                    remediation: "Add URL::forceScheme('https') to the boot() method of AppServiceProvider to ensure all generated URLs use HTTPS.",
                );
            }
        }
    }

    private function checkAppUrl(Context $ctx, array $env, string $envFile): iterable
    {
        $appUrl = $env['APP_URL'] ?? null;

        if ($appUrl !== null && str_starts_with($appUrl, 'http://')) {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: "APP_URL uses http:// instead of https:// in {$envFile}. This may cause mixed content issues and insecure URL generation.",
                file: $envFile,
                line: $this->findLine($ctx, $envFile, 'APP_URL'),
                symbol: 'APP_URL',
                snippet: "APP_URL={$appUrl}",
                remediation: "Change APP_URL to use https:// in {$envFile}.",
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
