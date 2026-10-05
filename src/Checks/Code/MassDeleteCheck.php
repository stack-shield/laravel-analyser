<?php

namespace StackShield\Analyser\Checks\Code;

use StackShield\Analyser\Checks\Advisory;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class MassDeleteCheck implements Advisory, Check
{
    private const DANGEROUS_PATTERNS = [
        '/\b\w+::truncate\s*\(\s*\)/' => 'Model::truncate() will delete all rows from the table without any conditions',
        '/DB::table\s*\([^)]+\)\s*->\s*delete\s*\(\s*\)/' => 'DB::table()->delete() without a where clause will delete all rows from the table',
        '/\b\w+::query\s*\(\s*\)\s*->\s*delete\s*\(\s*\)/' => 'Model::query()->delete() without constraints will delete all records',
    ];

    public function id(): string
    {
        return 'SS054';
    }

    public function name(): string
    {
        return 'Unconstrained Mass Delete Operations';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function category(): Category
    {
        return Category::Code;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $scanPaths = ['app/Http/Controllers', 'app/Console/Commands', 'app/Jobs', 'app/Actions'];

        foreach ($scanPaths as $scanPath) {
            foreach ($ctx->phpFiles($scanPath) as $file) {
                $contents = $ctx->fileContents($file);
                if ($contents === null) {
                    continue;
                }

                $lines = explode("\n", $contents);

                foreach ($lines as $index => $line) {
                    $trimmed = ltrim($line);
                    if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*') || str_starts_with($trimmed, '/*')) {
                        continue;
                    }

                    foreach (self::DANGEROUS_PATTERNS as $pattern => $description) {
                        if (preg_match($pattern, $line)) {
                            $lineNum = $index + 1;

                            yield new Finding(
                                checkId: $this->id(),
                                checkName: $this->name(),
                                checkVersion: $this->version(),
                                severity: $this->severity(),
                                category: $this->category(),
                                message: "{$description}. This could accidentally wipe production data.",
                                file: $file,
                                line: $lineNum,
                                symbol: 'mass_delete',
                                snippet: trim($line),
                                remediation: 'Add explicit where() constraints before delete(), or use soft deletes. For intentional truncations, add a confirmation step and audit logging.',
                            );

                            break; // One finding per line
                        }
                    }
                }
            }
        }
    }
}
