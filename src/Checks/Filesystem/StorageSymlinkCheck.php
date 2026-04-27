<?php

namespace Stackshield\Scanner\Checks\Filesystem;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class StorageSymlinkCheck implements Check
{
    public function id(): string
    {
        return 'SS021';
    }

    public function name(): string
    {
        return 'Storage Symlink Exposure';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
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
        $storagePath = $ctx->resolve('public/storage');

        if (! is_link($storagePath)) {
            return;
        }

        $target = readlink($storagePath);
        if ($target === false) {
            return;
        }

        // Resolve the real target
        $realTarget = realpath($storagePath);
        if ($realTarget === false) {
            return;
        }

        // Check if the symlink points somewhere unexpected (not storage/app/public)
        $expectedTarget = realpath($ctx->resolve('storage/app/public'));

        if ($expectedTarget !== false && $realTarget !== $expectedTarget) {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: Severity::High,
                category: $this->category(),
                message: "public/storage symlink points to {$target} instead of storage/app/public. This may expose unintended files.",
                file: 'public/storage',
                symbol: 'storage_symlink',
                remediation: 'Recreate the symlink with `php artisan storage:link` to point to the correct directory.',
            );
        }

        // Check for sensitive file patterns in the public storage
        $sensitivePatterns = ['*.sql', '*.sqlite', '*.log', '*.env', '*.key'];
        if (is_dir($realTarget)) {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($realTarget, \RecursiveDirectoryIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (! $file->isFile()) {
                    continue;
                }

                $ext = strtolower($file->getExtension());
                if (in_array($ext, ['sql', 'sqlite', 'log', 'env', 'key', 'pem'], true)) {
                    $relativePath = $ctx->relativize($file->getRealPath());
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: Severity::High,
                        category: $this->category(),
                        message: "Sensitive file {$file->getFilename()} found in publicly accessible storage directory.",
                        file: $relativePath,
                        symbol: $file->getFilename(),
                        remediation: 'Move sensitive files out of the public storage directory.',
                    );
                }
            }
        }
    }
}
