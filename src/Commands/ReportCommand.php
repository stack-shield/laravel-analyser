<?php

namespace Stackshield\Scanner\Commands;

use Illuminate\Console\Command;
use Stackshield\Scanner\Scanner;

class ReportCommand extends Command
{
    protected $signature = 'stackshield:report
        {--format=json : Output format (json, sarif, markdown, ai)}
        {--output= : Write output to file or directory}';

    protected $description = 'Generate a report from the last scan';

    public function handle(Scanner $scanner): int
    {
        $basePath = base_path();
        $format = $this->option('format');
        $outputPath = $this->option('output');

        if (count($scanner->checks()) === 0) {
            $this->warn('No checks registered.');

            return self::SUCCESS;
        }

        $report = $scanner->scan($basePath);

        if ($format === 'ai') {
            return $this->generateAiBundle($report, $outputPath ?? 'stackshield-fixes');
        }

        $reporter = match ($format) {
            'sarif' => new \Stackshield\Scanner\Reporters\SarifReporter,
            'markdown', 'md' => new \Stackshield\Scanner\Reporters\MarkdownReporter,
            default => new \Stackshield\Scanner\Reporters\JsonReporter,
        };

        $output = $reporter->render($report);

        if ($outputPath) {
            file_put_contents($outputPath, $output);
            $this->info("Report written to {$outputPath}");
        } else {
            $this->line($output);
        }

        return self::SUCCESS;
    }

    private function generateAiBundle(\Stackshield\Scanner\Report $report, string $outputDir): int
    {
        if (! is_dir($outputDir)) {
            mkdir($outputDir, 0755, true);
        }
        if (! is_dir("{$outputDir}/fixes")) {
            mkdir("{$outputDir}/fixes", 0755, true);
        }
        if (! is_dir("{$outputDir}/context")) {
            mkdir("{$outputDir}/context", 0755, true);
        }

        // Write findings.json
        $jsonReporter = new \Stackshield\Scanner\Reporters\JsonReporter;
        file_put_contents("{$outputDir}/findings.json", $jsonReporter->render($report));

        // Write per-finding fix files
        $relatedFiles = [];
        foreach ($report->findings() as $finding) {
            $filename = "{$finding->checkId}-".substr($finding->fingerprint, 0, 8).'.md';
            $content = "# {$finding->checkId}: {$finding->checkName}\n\n";
            $content .= "**Severity:** {$finding->severity->label()}\n";
            $content .= "**File:** `{$finding->file}`".($finding->line > 0 ? ":{$finding->line}" : '')."\n";
            if ($finding->symbol) {
                $content .= "**Symbol:** `{$finding->symbol}`\n";
            }
            $content .= "\n## Finding\n\n{$finding->message}\n";
            if ($finding->snippet) {
                $content .= "\n## Code\n\n```php\n{$finding->snippet}\n```\n";
            }
            if ($finding->remediation) {
                $content .= "\n## Remediation\n\n{$finding->remediation}\n";
            }

            file_put_contents("{$outputDir}/fixes/{$filename}", $content);
            $relatedFiles[] = $finding->file;
        }

        // Write related files context
        $relatedFiles = array_unique($relatedFiles);
        $contextContent = "# Related Files\n\nThese files contain findings and should be read before applying fixes:\n\n";
        foreach ($relatedFiles as $file) {
            $contextContent .= "- `{$file}`\n";
        }
        file_put_contents("{$outputDir}/context/related-files.md", $contextContent);

        // Write README entry point
        $readme = "# Stackshield Fix Bundle\n\n";
        $readme .= "This directory contains {$report->count()} security finding(s) detected by Stackshield Scanner.\n\n";
        $readme .= "## Instructions\n\n";
        $readme .= "1. Read `context/related-files.md` and open each listed file\n";
        $readme .= "2. Read each file in `fixes/` and apply the suggested remediation\n";
        $readme .= "3. Run your test suite after each fix\n";
        $readme .= "4. Run `php artisan stackshield:scan` to verify findings are resolved\n";
        $readme .= "5. Open a PR with all changes\n";
        file_put_contents("{$outputDir}/README.md", $readme);

        $this->info("AI fix bundle written to {$outputDir}/ with {$report->count()} finding(s).");

        return self::SUCCESS;
    }
}
