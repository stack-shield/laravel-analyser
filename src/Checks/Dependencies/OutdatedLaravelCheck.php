<?php

namespace Stackshield\Scanner\Checks\Dependencies;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class OutdatedLaravelCheck implements Check
{
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
        return 1;
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

        $majorVersion = (int) explode('.', $laravelVersion)[0];

        // End-of-life: below 10.x (Laravel 9 and earlier are EOL)
        if ($majorVersion < 10) {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: Severity::High,
                category: $this->category(),
                message: "Laravel {$laravelVersion} has reached end-of-life and no longer receives security patches. Your application is exposed to known unpatched vulnerabilities.",
                file: 'composer.lock',
                symbol: 'laravel/framework',
                snippet: "\"laravel/framework\": \"{$laravelVersion}\"",
                remediation: "Upgrade to a supported Laravel version (11.x LTS or later). See https://laravel.com/docs/releases for the support schedule.",
            );

            return;
        }

        // Below current LTS (11.x)
        if ($majorVersion < 11) {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: "Laravel {$laravelVersion} is behind the latest LTS release (11.x). Older versions receive security fixes for a limited time.",
                file: 'composer.lock',
                symbol: 'laravel/framework',
                snippet: "\"laravel/framework\": \"{$laravelVersion}\"",
                remediation: "Plan an upgrade to Laravel 11.x LTS for long-term security support. See https://laravel.com/docs/upgrade for the upgrade guide.",
            );
        }
    }
}
