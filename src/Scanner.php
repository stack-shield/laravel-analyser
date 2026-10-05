<?php

namespace StackShield\Analyser;

use StackShield\Analyser\Baseline\Baseline;
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
                $report->addFinding($finding);
            }
        }

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
