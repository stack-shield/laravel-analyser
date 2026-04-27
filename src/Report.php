<?php

namespace Stackshield\Scanner;

use Stackshield\Scanner\Enums\Severity;

final class Report
{
    /** @var Finding[] */
    private array $findings = [];

    private float $startTime;

    private ?float $endTime = null;

    public function __construct(
        public readonly string $scannerVersion,
        public readonly string $basePath,
    ) {
        $this->startTime = microtime(true);
    }

    public function addFinding(Finding $finding): void
    {
        $this->findings[] = $finding;
    }

    public function addFindings(iterable $findings): void
    {
        foreach ($findings as $finding) {
            $this->addFinding($finding);
        }
    }

    public function finish(): void
    {
        $this->endTime = microtime(true);
    }

    /** @return Finding[] */
    public function findings(): array
    {
        return $this->findings;
    }

    /** @return Finding[] */
    public function findingsBySeverity(Severity $severity): array
    {
        return array_filter($this->findings, fn (Finding $f) => $f->severity === $severity);
    }

    public function count(): int
    {
        return count($this->findings);
    }

    public function countBySeverity(): array
    {
        $counts = [];
        foreach (Severity::cases() as $severity) {
            $counts[$severity->value] = count($this->findingsBySeverity($severity));
        }

        return $counts;
    }

    public function duration(): float
    {
        return ($this->endTime ?? microtime(true)) - $this->startTime;
    }

    public function grade(): string
    {
        $counts = $this->countBySeverity();
        $critical = $counts['critical'] ?? 0;
        $high = $counts['high'] ?? 0;
        $medium = $counts['medium'] ?? 0;

        if ($critical === 0 && $high === 0 && $medium < 3) {
            return 'A';
        }
        if ($critical === 0 && $high <= 1 && $medium < 6) {
            return 'B';
        }
        if ($high <= 2) {
            return 'C';
        }

        return 'D';
    }

    public function toArray(): array
    {
        return [
            'scanner_version' => $this->scannerVersion,
            'base_path' => $this->basePath,
            'grade' => $this->grade(),
            'duration' => round($this->duration(), 3),
            'finding_counts' => $this->countBySeverity(),
            'total_findings' => $this->count(),
            'findings' => array_map(fn (Finding $f) => $f->toArray(), $this->findings),
        ];
    }
}
