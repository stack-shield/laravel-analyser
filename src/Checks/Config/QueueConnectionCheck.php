<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class QueueConnectionCheck implements Check
{
    public function id(): string
    {
        return 'SS047';
    }

    public function name(): string
    {
        return 'Synchronous Queue in Production';
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

            $queueConnection = $env['QUEUE_CONNECTION'] ?? null;
            if ($queueConnection === 'sync') {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "QUEUE_CONNECTION is set to 'sync' in {$envFile}. Jobs will execute synchronously during HTTP requests, blocking responses and preventing retry on failure.",
                    file: $envFile,
                    line: $this->findLine($ctx, $envFile, 'QUEUE_CONNECTION'),
                    symbol: 'QUEUE_CONNECTION',
                    snippet: "QUEUE_CONNECTION={$queueConnection}",
                    remediation: "Set QUEUE_CONNECTION to 'redis', 'database', or 'sqs' in {$envFile} for asynchronous job processing.",
                );
            }
        }

        // Also check the main .env if it looks like a production env
        $mainEnv = $ctx->env('.env');
        if (! empty($mainEnv)) {
            $appEnv = $mainEnv['APP_ENV'] ?? null;
            $queueConnection = $mainEnv['QUEUE_CONNECTION'] ?? null;

            if ($appEnv === 'production' && $queueConnection === 'sync') {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "QUEUE_CONNECTION is set to 'sync' in .env while APP_ENV=production. Jobs will execute synchronously, blocking HTTP requests.",
                    file: '.env',
                    line: $this->findLine($ctx, '.env', 'QUEUE_CONNECTION'),
                    symbol: 'QUEUE_CONNECTION',
                    snippet: "QUEUE_CONNECTION={$queueConnection}",
                    remediation: "Set QUEUE_CONNECTION to 'redis', 'database', or 'sqs' in .env for asynchronous job processing.",
                );
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
            if (str_starts_with(trim($line), $key . '=')) {
                return $i + 1;
            }
        }

        return 0;
    }
}
