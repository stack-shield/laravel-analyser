<?php

namespace Stackshield\Scanner\Commands;

use Illuminate\Console\Command;
use Stackshield\Scanner\Baseline\Baseline;
use Stackshield\Scanner\Reporters\ConsoleReporter;
use Stackshield\Scanner\Reporters\JsonReporter;
use Stackshield\Scanner\Reporters\MarkdownReporter;
use Stackshield\Scanner\Reporters\SarifReporter;
use Stackshield\Scanner\Scanner;

class ScanCommand extends Command
{
    protected $signature = 'stackshield:scan
        {--format=console : Output format (console, json, sarif, markdown)}
        {--output= : Write output to file instead of stdout}
        {--baseline= : Path to baseline file}
        {--fail-on=high : Minimum severity to fail on (info, low, medium, high, critical)}';

    protected $description = 'Run Stackshield security scan';

    public function handle(Scanner $scanner): int
    {
        $basePath = base_path();
        $format = $this->option('format');
        $outputPath = $this->option('output');

        // Load baseline if specified
        $baselinePath = $this->option('baseline');
        if ($baselinePath && file_exists($baselinePath)) {
            $scanner->setBaseline(Baseline::fromFile($baselinePath));
        } elseif (file_exists($basePath.'/stackshield-baseline.yaml')) {
            $scanner->setBaseline(Baseline::fromFile($basePath.'/stackshield-baseline.yaml'));
        }

        if (count($scanner->checks()) === 0) {
            $this->warn('No checks registered. Add checks to your configuration.');

            return self::SUCCESS;
        }

        $report = $scanner->scan($basePath);

        $reporter = match ($format) {
            'json' => new JsonReporter,
            'sarif' => new SarifReporter,
            'markdown', 'md' => new MarkdownReporter,
            default => new ConsoleReporter,
        };

        $output = $reporter->render($report);

        if ($outputPath) {
            file_put_contents($outputPath, $output);
            $this->info("Report written to {$outputPath}");
        } else {
            $this->line($output);
        }

        // Determine exit code based on fail-on severity
        $failOn = $this->option('fail-on');
        $severityMap = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        $failThreshold = $severityMap[$failOn] ?? 3;

        foreach ($report->countBySeverity() as $severity => $count) {
            if ($count > 0 && ($severityMap[$severity] ?? 0) >= $failThreshold) {
                return self::FAILURE;
            }
        }

        return self::SUCCESS;
    }
}
