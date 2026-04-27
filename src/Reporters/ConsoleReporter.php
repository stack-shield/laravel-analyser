<?php

namespace Stackshield\Scanner\Reporters;

use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;
use Stackshield\Scanner\Report;

final class ConsoleReporter implements Reporter
{
    public function render(Report $report): string
    {
        $output = [];
        $output[] = '';
        $output[] = '  Stackshield Security Scan';
        $output[] = '  '.str_repeat('=', 50);
        $output[] = '';

        if ($report->count() === 0) {
            $output[] = '  No findings. Grade: A';
            $output[] = '';
            $output[] = '  Scan completed in '.round($report->duration(), 2).'s';
            $output[] = '';

            return implode("\n", $output);
        }

        // Group by severity (highest first)
        $severities = array_reverse(Severity::cases());

        foreach ($severities as $severity) {
            $findings = $report->findingsBySeverity($severity);
            if (empty($findings)) {
                continue;
            }

            $output[] = "  [{$severity->label()}] ".count($findings).' finding(s)';
            $output[] = '  '.str_repeat('-', 40);

            /** @var Finding $finding */
            foreach ($findings as $finding) {
                $location = $finding->file;
                if ($finding->line > 0) {
                    $location .= ':'.$finding->line;
                }

                $output[] = "  {$finding->checkId}: {$finding->message}";
                $output[] = "    -> {$location}";
                if ($finding->remediation) {
                    $output[] = "    Fix: {$finding->remediation}";
                }
            }

            $output[] = '';
        }

        $counts = $report->countBySeverity();
        $summary = [];
        foreach ($counts as $sev => $count) {
            if ($count > 0) {
                $summary[] = "{$count} {$sev}";
            }
        }

        $output[] = '  Grade: '.$report->grade().' | '.implode(', ', $summary);
        $output[] = '  Scan completed in '.round($report->duration(), 2).'s';
        $output[] = '';

        return implode("\n", $output);
    }
}
