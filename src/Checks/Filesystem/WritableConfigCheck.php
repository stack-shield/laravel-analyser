<?php

namespace StackShield\Analyser\Checks\Filesystem;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class WritableConfigCheck implements Check
{
    public function id(): string
    {
        return 'SS057';
    }

    public function name(): string
    {
        return 'Writable Configuration Files';
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
        $configDir = $ctx->resolve('config');
        if (! is_dir($configDir)) {
            return;
        }

        $iterator = new \DirectoryIterator($configDir);

        foreach ($iterator as $fileInfo) {
            if ($fileInfo->isDot() || $fileInfo->getExtension() !== 'php') {
                continue;
            }

            $path = $fileInfo->getRealPath();
            if ($path === false) {
                continue;
            }

            $perms = fileperms($path);
            if ($perms === false) {
                continue;
            }

            // Check if group-writable or world-writable
            $groupWrite = ($perms & 0x0010);
            $otherWrite = ($perms & 0x0002);

            if ($otherWrite) {
                $relativePath = 'config/'.$fileInfo->getFilename();
                $permString = substr(sprintf('%o', $perms), -4);

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: Severity::High,
                    category: $this->category(),
                    message: "{$relativePath} is world-writable (permissions: {$permString}). An attacker with local access could modify application configuration.",
                    file: $relativePath,
                    symbol: 'file_permissions',
                    snippet: $permString,
                    remediation: "Remove write permissions: chmod 644 {$relativePath} (or 440 for stricter production environments).",
                );
            } elseif ($groupWrite) {
                $relativePath = 'config/'.$fileInfo->getFilename();
                $permString = substr(sprintf('%o', $perms), -4);

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "{$relativePath} is group-writable (permissions: {$permString}). In production, config files should be read-only after deployment.",
                    file: $relativePath,
                    symbol: 'file_permissions',
                    snippet: $permString,
                    remediation: "Remove group write permissions: chmod 644 {$relativePath}",
                );
            }
        }
    }
}
