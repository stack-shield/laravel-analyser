<?php

namespace Stackshield\Scanner\Checks\Dependencies;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class InsecurePackagesCheck implements Check
{
    /**
     * Known-insecure packages and the minimum safe major version.
     * Format: package => [minimum_safe_major, description]
     */
    private const INSECURE_PACKAGES = [
        'phpmailer/phpmailer' => [
            'min_major' => 6,
            'description' => 'PHPMailer < 6.0 has known remote code execution and header injection vulnerabilities (CVE-2016-10033, CVE-2016-10045)',
        ],
        'guzzlehttp/guzzle' => [
            'min_major' => 7,
            'description' => 'Guzzle < 7.0 has known security issues including improper header handling and cookie validation vulnerabilities',
        ],
        'league/flysystem' => [
            'min_major' => 3,
            'description' => 'Flysystem < 3.0 has known path traversal and symlink vulnerabilities',
        ],
    ];

    public function id(): string
    {
        return 'SS056';
    }

    public function name(): string
    {
        return 'Known Insecure Package Versions';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $composerJson = $ctx->composerJson();
        if (empty($composerJson)) {
            return;
        }

        $require = $composerJson['require'] ?? [];
        $requireDev = $composerJson['require-dev'] ?? [];
        $allDeps = array_merge($require, $requireDev);

        foreach (self::INSECURE_PACKAGES as $packageName => $info) {
            if (! isset($allDeps[$packageName])) {
                continue;
            }

            $constraint = $allDeps[$packageName];
            $minMajor = $info['min_major'];

            // Check if the constraint could resolve to a version below the minimum safe major
            if ($this->constraintAllowsInsecure($constraint, $minMajor)) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "{$packageName} is constrained to \"{$constraint}\" which may allow insecure versions. {$info['description']}.",
                    file: 'composer.json',
                    symbol: $packageName,
                    snippet: "\"{$packageName}\": \"{$constraint}\"",
                    remediation: "Update the version constraint to require at least {$packageName} ^{$minMajor}.0: composer require {$packageName}:^{$minMajor}.0",
                );
            }
        }
    }

    private function constraintAllowsInsecure(string $constraint, int $minMajor): bool
    {
        // Remove spaces
        $constraint = trim($constraint);

        // Wildcard - allows anything
        if ($constraint === '*') {
            return true;
        }

        // Extract version numbers from the constraint
        // Handle ^, ~, >=, >, <=, <, exact versions
        if (preg_match('/(\d+)/', $constraint, $matches)) {
            $constraintMajor = (int) $matches[1];

            // ^X.Y or ~X.Y or X.Y.* - the major version determines the floor
            if (str_starts_with($constraint, '^') || str_starts_with($constraint, '~')) {
                return $constraintMajor < $minMajor;
            }

            // >=X.Y
            if (str_starts_with($constraint, '>=')) {
                return $constraintMajor < $minMajor;
            }

            // >X.Y
            if (str_starts_with($constraint, '>') && ! str_starts_with($constraint, '>=')) {
                return $constraintMajor < $minMajor;
            }

            // Exact version or version with .* wildcard
            return $constraintMajor < $minMajor;
        }

        return false;
    }
}
