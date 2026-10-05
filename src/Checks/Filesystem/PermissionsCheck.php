<?php

namespace StackShield\Analyser\Checks\Filesystem;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class PermissionsCheck implements Check
{
    public function id(): string
    {
        return 'SS022';
    }

    public function name(): string
    {
        return 'Insecure File Permissions';
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
        $sensitiveFiles = ['.env', 'config/database.php', 'config/app.php', 'storage/logs'];

        foreach ($sensitiveFiles as $file) {
            $path = $ctx->resolve($file);
            if (! file_exists($path)) {
                continue;
            }

            $perms = fileperms($path);
            if ($perms === false) {
                continue;
            }

            // Check if world-readable (others have read permission)
            $otherRead = ($perms & 0x0004);
            $otherWrite = ($perms & 0x0002);

            if ($otherWrite) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: Severity::High,
                    category: $this->category(),
                    message: "{$file} is world-writable (permissions: ".substr(sprintf('%o', $perms), -4).'). Any user on the system can modify it.',
                    file: $file,
                    symbol: 'file_permissions',
                    remediation: "Run: chmod 640 {$file}",
                );
            } elseif ($otherRead && str_contains($file, '.env')) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "{$file} is world-readable (permissions: ".substr(sprintf('%o', $perms), -4).'). Secrets may be exposed to other users on shared hosting.',
                    file: $file,
                    symbol: 'file_permissions',
                    remediation: "Run: chmod 600 {$file}",
                );
            }
        }
    }
}
