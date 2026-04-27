<?php

namespace Stackshield\Scanner;

use Illuminate\Support\ServiceProvider;
use Stackshield\Scanner\Commands\BaselineCommand;
use Stackshield\Scanner\Commands\ChecksCommand;
use Stackshield\Scanner\Commands\ReportCommand;
use Stackshield\Scanner\Commands\ScanCommand;
use Symfony\Component\Yaml\Yaml;

class ScannerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Scanner::class, function () {
            $config = $this->loadConfig();
            $scanner = new Scanner($config);
            $this->registerDefaultChecks($scanner, $config);

            return $scanner;
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                ScanCommand::class,
                BaselineCommand::class,
                ChecksCommand::class,
                ReportCommand::class,
            ]);
        }
    }

    private function loadConfig(): array
    {
        $configPath = base_path('stackshield.yaml');
        if (! file_exists($configPath)) {
            return [];
        }

        return Yaml::parseFile($configPath) ?? [];
    }

    private function registerDefaultChecks(Scanner $scanner, array $config): void
    {
        $checks = [
            new Checks\Config\DebugModeCheck,
            new Checks\Config\AppKeyCheck,
            new Checks\Config\DevToolsProductionCheck,
            new Checks\Config\SessionCookieCheck,
            new Checks\Code\MassAssignmentCheck,
            new Checks\Filesystem\ExposedFilesCheck,
            new Checks\Filesystem\StorageSymlinkCheck,
            new Checks\Routes\AuthThrottleCheck,
            new Checks\Routes\RouteModelBindingAuthCheck,
            new Checks\Routes\CsrfExemptionCheck,
            new Checks\Code\RawSqlCheck,
            new Checks\Code\DangerousSinksCheck,
        ];

        $scanner->registerChecks($checks);
    }
}
