<?php

namespace Stackshield\Scanner;

use Illuminate\Support\ServiceProvider;
use Stackshield\Scanner\Commands\BaselineCommand;
use Stackshield\Scanner\Commands\ChecksCommand;
use Stackshield\Scanner\Commands\FixCommand;
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
                FixCommand::class,
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
            // Code checks
            new Checks\Code\MassAssignmentCheck,          // SS001
            new Checks\Code\RawSqlCheck,                  // SS002
            new Checks\Code\DangerousSinksCheck,          // SS003
            new Checks\Code\UnvalidatedInputCheck,        // SS007
            new Checks\Code\HardcodedCredentialsCheck,    // SS008
            new Checks\Code\FileUploadCheck,              // SS009
            // Config checks
            new Checks\Config\AppKeyCheck,                // SS010
            new Checks\Config\EncryptionConfigCheck,      // SS011
            new Checks\Config\DebugModeCheck,             // SS012
            new Checks\Config\DevToolsProductionCheck,    // SS013
            new Checks\Config\LogChannelCheck,            // SS014
            new Checks\Config\SessionCookieCheck,         // SS015
            new Checks\Config\CorsConfigCheck,            // SS016
            new Checks\Config\MailConfigCheck,            // SS017
            // Route checks
            new Checks\Routes\AuthThrottleCheck,          // SS004
            new Checks\Routes\RouteModelBindingAuthCheck, // SS005
            new Checks\Routes\CsrfExemptionCheck,        // SS006
            // Filesystem checks
            new Checks\Filesystem\ExposedFilesCheck,      // SS020
            new Checks\Filesystem\StorageSymlinkCheck,    // SS021
            new Checks\Filesystem\PermissionsCheck,       // SS022
            // Dependency checks
            new Checks\Dependencies\KnownAdvisoriesCheck, // SS030
        ];

        $scanner->registerChecks($checks);
    }
}
