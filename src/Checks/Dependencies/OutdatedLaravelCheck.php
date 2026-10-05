<?php

namespace StackShield\Analyser\Checks\Dependencies;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class OutdatedLaravelCheck implements Check
{
    /**
     * End of security fixes per major, from laravel.com/docs/releases. Laravel
     * has had no LTS releases since 9; each major gets two years of security
     * fixes. Majors before 10 are long past theirs.
     */
    private const SECURITY_EOL = [
        10 => '2025-02-04',
        11 => '2026-03-12',
        12 => '2027-02-24',
        13 => '2028-03-17',
    ];

    public function id(): string
    {
        return 'SS055';
    }

    public function name(): string
    {
        return 'Outdated Laravel Framework Version';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function version(): int
    {
        return 2;
    }

    public function run(Context $ctx): iterable
    {
        $lock = $ctx->composerLock();
        if (empty($lock)) {
            return;
        }

        $packages = array_merge(
            $lock['packages'] ?? [],
            $lock['packages-dev'] ?? []
        );

        $laravelVersion = null;
        foreach ($packages as $package) {
            if (($package['name'] ?? '') === 'laravel/framework') {
                $laravelVersion = ltrim($package['version'] ?? '', 'v');
                break;
            }
        }

        if ($laravelVersion === null) {
            return;
        }

        $major = (int) explode('.', $laravelVersion)[0];
        $eol = self::SECURITY_EOL[$major] ?? ($major < 10 ? '2024-02-06' : null);
        if ($eol === null || time() < strtotime($eol)) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            checkName: $this->name(),
            checkVersion: $this->version(),
            severity: Severity::High,
            category: $this->category(),
            message: "Laravel {$laravelVersion} stopped receiving security fixes on {$eol}. Vulnerabilities found since then are not patched.",
            file: 'composer.lock',
            symbol: 'laravel/framework',
            snippet: "\"laravel/framework\": \"{$laravelVersion}\"",
            remediation: 'Upgrade to a Laravel version that still receives security fixes. See https://laravel.com/docs/releases for the support schedule.',
        );
    }
}
