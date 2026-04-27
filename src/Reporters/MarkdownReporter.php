<?php

namespace Stackshield\Scanner\Reporters;

use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;
use Stackshield\Scanner\Report;

final class MarkdownReporter implements Reporter
{
    public function render(Report $report): string
    {
        $lines = [];
        $lines[] = '# Stackshield Security Scan';
        $lines[] = '';
        $lines[] = "**Grade:** {$report->grade()} | **Findings:** {$report->count()} | **Duration:** ".round($report->duration(), 2).'s';
        $lines[] = '';

        if ($report->count() === 0) {
            $lines[] = 'No security findings detected.';

            return implode("\n", $lines);
        }

        $lines[] = '## Summary';
        $lines[] = '';
        $lines[] = '| Severity | Count |';
        $lines[] = '|----------|-------|';
        foreach ($report->countBySeverity() as $severity => $count) {
            if ($count > 0) {
                $lines[] = "| {$severity} | {$count} |";
            }
        }
        $lines[] = '';

        $severities = array_reverse(Severity::cases());

        foreach ($severities as $severity) {
            $findings = $report->findingsBySeverity($severity);
            if (empty($findings)) {
                continue;
            }

            $lines[] = "## {$severity->label()} (".count($findings).')';
            $lines[] = '';

            foreach ($findings as $finding) {
                $location = $finding->file;
                if ($finding->line > 0) {
                    $location .= ':'.$finding->line;
                }

                $lines[] = "### {$finding->checkId}: {$finding->checkName}";
                $lines[] = '';
                $lines[] = $finding->message;
                $lines[] = '';
                $lines[] = "**File:** `{$location}`";
                if ($finding->remediation) {
                    $lines[] = '';
                    $lines[] = "**Fix:** {$finding->remediation}";
                }
                $lines[] = '';
            }
        }

        return implode("\n", $lines);
    }
}
