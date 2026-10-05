<?php

namespace StackShield\Analyser\Commands;

use Illuminate\Console\Command;
use StackShield\Analyser\Finding;
use StackShield\Analyser\Scanner;

class FixCommand extends Command
{
    protected $signature = 'stackshield:analyse-fix
        {--check= : Only fix findings for a specific check ID}
        {--dry-run : Show what would be fixed without making changes}';

    protected $description = 'Auto-fix mechanical security findings';

    private const FIXABLE_CHECKS = ['SS001', 'SS012', 'SS004'];

    public function handle(Scanner $scanner): int
    {
        $basePath = base_path();
        $report = $scanner->scan($basePath);
        $checkFilter = $this->option('check');
        $dryRun = $this->option('dry-run');

        $fixable = array_filter(
            $report->findings(),
            fn (Finding $f) => in_array($f->checkId, self::FIXABLE_CHECKS, true)
                && ($checkFilter === null || $f->checkId === $checkFilter)
        );

        if (empty($fixable)) {
            $this->info('No auto-fixable findings found.');

            return self::SUCCESS;
        }

        $this->info('Found '.count($fixable).' auto-fixable finding(s).');

        $fixed = 0;
        foreach ($fixable as $finding) {
            $result = match ($finding->checkId) {
                'SS001' => $this->fixMassAssignment($finding, $basePath, $dryRun),
                'SS012' => $this->fixDebugMode($finding, $basePath, $dryRun),
                'SS004' => $this->fixAuthThrottle($finding, $basePath, $dryRun),
                default => false,
            };

            if ($result) {
                $fixed++;
                $status = $dryRun ? 'Would fix' : 'Fixed';
                $this->line("  [{$status}] {$finding->checkId}: {$finding->file}");
            }
        }

        $action = $dryRun ? 'would be fixed' : 'fixed';
        $this->info("{$fixed} finding(s) {$action}.");

        return self::SUCCESS;
    }

    private function fixMassAssignment(Finding $finding, string $basePath, bool $dryRun): bool
    {
        $filePath = $basePath.'/'.$finding->file;
        if (! file_exists($filePath)) {
            return false;
        }

        if ($dryRun) {
            return true;
        }

        $contents = file_get_contents($filePath);

        // Add protected $fillable = []; after the class opening or use statements
        $pattern = '/(class\s+\w+\s+extends\s+\w+\s*\{(?:\s*use\s+[^;]+;\s*)*)/s';

        if (preg_match($pattern, $contents, $matches)) {
            $replacement = $matches[1]."\n    protected \$fillable = [];\n";
            $contents = str_replace($matches[1], $replacement, $contents);
            file_put_contents($filePath, $contents);

            return true;
        }

        return false;
    }

    private function fixDebugMode(Finding $finding, string $basePath, bool $dryRun): bool
    {
        $filePath = $basePath.'/'.$finding->file;
        if (! file_exists($filePath)) {
            return false;
        }

        if ($dryRun) {
            return true;
        }

        $contents = file_get_contents($filePath);
        $contents = preg_replace('/^APP_DEBUG\s*=\s*(true|1|yes|on)\s*$/mi', 'APP_DEBUG=false', $contents);
        file_put_contents($filePath, $contents);

        return true;
    }

    private function fixAuthThrottle(Finding $finding, string $basePath, bool $dryRun): bool
    {
        // This is harder to auto-fix reliably, so just report
        if ($dryRun) {
            return true;
        }

        $this->warn("  SS004: Manual fix needed for {$finding->file}. Add ->middleware('throttle:5,1') to auth routes.");

        return false;
    }
}
