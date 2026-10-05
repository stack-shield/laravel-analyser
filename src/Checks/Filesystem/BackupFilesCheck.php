<?php

namespace StackShield\Analyser\Checks\Filesystem;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class BackupFilesCheck implements Check
{
    private const DANGEROUS_EXTENSIONS = [
        'sql' => 'SQL dump file may contain database schema and data',
        'sql.gz' => 'Compressed SQL dump may contain database schema and data',
        'bak' => 'Backup file may contain sensitive application data',
        'tar.gz' => 'Archive file may contain application source code or data',
        'zip' => 'Archive file may contain application source code or data',
    ];

    private const DANGEROUS_FILENAMES = [
        'database.sqlite' => 'SQLite database file contains application data',
    ];

    public function id(): string
    {
        return 'SS058';
    }

    public function name(): string
    {
        return 'Backup Files in Public Directory';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function category(): Category
    {
        return Category::Filesystem;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $publicDir = $ctx->resolve('public');
        if (! is_dir($publicDir)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($publicDir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if (! $file->isFile()) {
                continue;
            }

            $filename = $file->getFilename();
            $relativePath = $ctx->relativize($file->getRealPath());

            // Check for dangerous filenames
            if (isset(self::DANGEROUS_FILENAMES[$filename])) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "{$filename} found in public directory. ".self::DANGEROUS_FILENAMES[$filename].'.',
                    file: $relativePath,
                    symbol: $filename,
                    snippet: $filename,
                    remediation: "Remove {$filename} from the public/ directory immediately. Store database files outside the web root.",
                );

                continue;
            }

            // Check for dangerous extensions (including compound extensions like .sql.gz, .tar.gz)
            foreach (self::DANGEROUS_EXTENSIONS as $ext => $description) {
                if (str_ends_with(strtolower($filename), '.'.$ext)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: "Backup file '{$filename}' found in public directory. {$description}. Anyone with the URL can download it.",
                        file: $relativePath,
                        symbol: $filename,
                        snippet: $filename,
                        remediation: "Remove '{$filename}' from the public/ directory. Store backups outside the web root or in a secure cloud storage bucket.",
                    );

                    break; // One finding per file
                }
            }
        }
    }
}
