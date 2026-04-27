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
            new Checks\Code\InsecureRandomCheck,          // SS040
            new Checks\Code\OpenRedirectCheck,            // SS041
            new Checks\Code\WeakHashingCheck,             // SS042
            new Checks\Code\UnsafeDeserializationCheck,   // SS043
            new Checks\Code\BladeRawOutputCheck,          // SS044
            new Checks\Code\AuthorizationCheck,           // SS053
            new Checks\Code\MassDeleteCheck,              // SS054
            // Config checks
            new Checks\Config\AppKeyCheck,                // SS010
            new Checks\Config\EncryptionConfigCheck,      // SS011
            new Checks\Config\DebugModeCheck,             // SS012
            new Checks\Config\DevToolsProductionCheck,    // SS013
            new Checks\Config\LogChannelCheck,            // SS014
            new Checks\Config\SessionCookieCheck,         // SS015
            new Checks\Config\CorsConfigCheck,            // SS016
            new Checks\Config\MailConfigCheck,            // SS017
            new Checks\Config\TrustedProxiesCheck,        // SS045
            new Checks\Config\BroadcastingAuthCheck,      // SS046
            new Checks\Config\QueueConnectionCheck,       // SS047
            new Checks\Config\CacheDriverCheck,           // SS048
            new Checks\Config\ForceHttpsCheck,            // SS049
            // Route checks
            new Checks\Routes\AuthThrottleCheck,          // SS004
            new Checks\Routes\RouteModelBindingAuthCheck, // SS005
            new Checks\Routes\CsrfExemptionCheck,        // SS006
            new Checks\Routes\ApiRateLimitCheck,          // SS050
            new Checks\Routes\DebugRoutesCheck,           // SS051
            new Checks\Routes\WildcardRouteCheck,         // SS052
            // Filesystem checks
            new Checks\Filesystem\ExposedFilesCheck,      // SS020
            new Checks\Filesystem\StorageSymlinkCheck,    // SS021
            new Checks\Filesystem\PermissionsCheck,       // SS022
            new Checks\Filesystem\WritableConfigCheck,    // SS057
            new Checks\Filesystem\BackupFilesCheck,       // SS058
            // Dependency checks
            new Checks\Dependencies\KnownAdvisoriesCheck, // SS030
            new Checks\Dependencies\OutdatedLaravelCheck, // SS055
            new Checks\Dependencies\InsecurePackagesCheck, // SS056
        ];

        $scanner->registerChecks($checks);
    }
}
