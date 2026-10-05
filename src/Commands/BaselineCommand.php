<?php

namespace StackShield\Analyser\Commands;

use Illuminate\Console\Command;
use StackShield\Analyser\Baseline\Baseline;
use StackShield\Analyser\Scanner;

class BaselineCommand extends Command
{
    protected $signature = 'stackshield:analyse-baseline
        {--output=stackshield-baseline.yaml : Output path for baseline file}
        {--add : Only add new findings, keep existing entries}
        {--prune : Remove entries for findings no longer present}';

    protected $description = 'Generate or update the baseline file';

    public function handle(Scanner $scanner): int
    {
        $basePath = base_path();
        $outputPath = $this->option('output');

        if (count($scanner->checks()) === 0) {
            $this->warn('No checks registered. Add checks to your configuration.');

            return self::SUCCESS;
        }

        // Run scan without baseline filtering
        $report = $scanner->scan($basePath);
        $currentFindings = $report->findings();

        if ($this->option('add') && file_exists($outputPath)) {
            $existing = Baseline::fromFile($outputPath);
            $existingFingerprints = array_keys($existing->entries());

            $newFindings = array_filter(
                $currentFindings,
                fn ($f) => ! in_array($f->fingerprint, $existingFingerprints)
            );

            if (empty($newFindings)) {
                $this->info('No new findings to add to baseline.');

                return self::SUCCESS;
            }

            // Merge: keep existing + add new
            $allEntries = $existing->entries();
            foreach ($newFindings as $finding) {
                $allEntries[$finding->fingerprint] = [
                    'fingerprint' => $finding->fingerprint,
                    'check' => $finding->checkId,
                    'check_version' => $finding->checkVersion,
                    'file' => $finding->file,
                    'symbol' => $finding->symbol,
                    'first_seen' => date('Y-m-d'),
                    'note' => null,
                ];
            }

            $data = [
                'version' => 1,
                'generated_at' => date('c'),
                'generator' => 'stackshield-scanner@'.\StackShield\Analyser\Scanner::VERSION,
                'findings' => array_values($allEntries),
            ];

            file_put_contents($outputPath, \Symfony\Component\Yaml\Yaml::dump($data, 4, 2));
            $this->info('Added '.count($newFindings).' new finding(s) to baseline.');

            return self::SUCCESS;
        }

        if ($this->option('prune') && file_exists($outputPath)) {
            $existing = Baseline::fromFile($outputPath);
            $currentFingerprints = array_map(fn ($f) => $f->fingerprint, $currentFindings);

            $pruned = array_filter(
                $existing->entries(),
                fn ($entry) => in_array($entry['fingerprint'], $currentFingerprints)
            );

            $removed = $existing->count() - count($pruned);

            $data = [
                'version' => 1,
                'generated_at' => date('c'),
                'generator' => 'stackshield-scanner@'.\StackShield\Analyser\Scanner::VERSION,
                'findings' => array_values($pruned),
            ];

            file_put_contents($outputPath, \Symfony\Component\Yaml\Yaml::dump($data, 4, 2));
            $this->info("Pruned {$removed} fixed finding(s) from baseline.");

            return self::SUCCESS;
        }

        // Full regenerate
        Baseline::write($outputPath, $currentFindings);
        $this->info("Baseline written with {$report->count()} finding(s) to {$outputPath}");

        return self::SUCCESS;
    }
}
