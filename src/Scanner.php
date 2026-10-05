<?php

namespace StackShield\Analyser;

use StackShield\Analyser\Baseline\Baseline;
use StackShield\Analyser\Checks\Advisory;
use StackShield\Analyser\Checks\Check;

final class Scanner
{
    public const VERSION = '0.1.0';

    /** @var Check[] */
    private array $checks = [];

    private ?Baseline $baseline = null;

    public function __construct(
        private readonly array $config = [],
    ) {}

    /**
     * A scanner with every built-in check registered. Usable without booting
     * Laravel, which is how StackShield scans repositories it has downloaded.
     */
    public static function withDefaultChecks(array $config = []): self
    {
        $scanner = new self($config);
        $scanner->registerChecks([
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
        ]);

        return $scanner;
    }

    public function registerCheck(Check $check): void
    {
        $this->checks[$check->id()] = $check;
    }

    /** @param Check[] $checks */
    public function registerChecks(array $checks): void
    {
        foreach ($checks as $check) {
            $this->registerCheck($check);
        }
    }

    public function setBaseline(Baseline $baseline): void
    {
        $this->baseline = $baseline;
    }

    /** @return Check[] */
    public function checks(): array
    {
        return $this->checks;
    }

    public function scan(string $basePath): Report
    {
        $context = new Context($basePath, $this->config);
        $report = new Report(self::VERSION, $basePath);

        $enabledChecks = $this->resolveEnabledChecks();

        foreach ($enabledChecks as $check) {
            $findings = $check->run($context);
            foreach ($findings as $finding) {
                if ($this->baseline && $this->baseline->isSuppressed($finding)) {
                    continue;
                }
                $report->addFinding($check instanceof Advisory ? $finding->asAdvisory() : $finding);
            }
        }

        $report->setUnparseableFiles($context->unparseableFiles());
        $report->finish();

        return $report;
    }

    /** @return Check[] */
    private function resolveEnabledChecks(): array
    {
        $checksConfig = $this->config['checks'] ?? [];

        return array_filter($this->checks, function (Check $check) use ($checksConfig) {
            $checkConfig = $checksConfig[$check->id()] ?? [];

            return ($checkConfig['enabled'] ?? true) !== false;
        });
    }
}
