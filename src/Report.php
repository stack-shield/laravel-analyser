<?php

namespace StackShield\Analyser;

use StackShield\Analyser\Enums\Severity;

final class Report
{
    /** @var Finding[] */
    private array $findings = [];

    private float $startTime;

    private ?float $endTime = null;

    /** @var string[] */
    private array $unparseableFiles = [];

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

    /** @param string[] $files */
    public function setUnparseableFiles(array $files): void
    {
        $this->unparseableFiles = $files;
    }

    /** @return string[] */
    public function unparseableFiles(): array
    {
        return $this->unparseableFiles;
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

    /** @return Finding[] Findings that count toward the grade. */
    public function gradedFindings(): array
    {
        return array_values(array_filter($this->findings, fn (Finding $f) => ! $f->advisory));
    }

    /** @return Finding[] */
    public function advisoryFindings(): array
    {
        return array_values(array_filter($this->findings, fn (Finding $f) => $f->advisory));
    }

    /** Counts of graded findings by severity. Advisory findings are excluded. */
    public function countBySeverity(): array
    {
        return $this->tally($this->gradedFindings());
    }

    public function advisoryCountBySeverity(): array
    {
        return $this->tally($this->advisoryFindings());
    }

    /** @param Finding[] $findings */
    private function tally(array $findings): array
    {
        $counts = [];
        foreach (Severity::cases() as $severity) {
            $counts[$severity->value] = count(array_filter($findings, fn (Finding $f) => $f->severity === $severity));
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
            'advisory_counts' => $this->advisoryCountBySeverity(),
            'total_findings' => $this->count(),
            'unparseable_files' => $this->unparseableFiles,
            'findings' => array_map(fn (Finding $f) => $f->toArray(), $this->findings),
        ];
    }
}
