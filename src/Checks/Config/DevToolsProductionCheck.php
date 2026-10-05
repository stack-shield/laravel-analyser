<?php

namespace StackShield\Analyser\Checks\Config;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class DevToolsProductionCheck implements Check
{
    private const DEV_PACKAGES = [
        'laravel/telescope' => 'Telescope',
        'laravel/horizon' => 'Horizon',
        'barryvdh/laravel-debugbar' => 'Debugbar',
        'beyondcode/laravel-dump-server' => 'Dump Server',
        'facade/ignition' => 'Ignition',
        'spatie/laravel-ignition' => 'Ignition',
    ];

    public function id(): string
    {
        return 'SS013';
    }

    public function name(): string
    {
        return 'Dev Tools in Production';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $composerJson = $ctx->composerJson();
        $require = $composerJson['require'] ?? [];
        $requireDev = $composerJson['require-dev'] ?? [];

        foreach (self::DEV_PACKAGES as $package => $label) {
            // Flag if in require (not require-dev)
            if (isset($require[$package])) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "{$label} ({$package}) is in `require` instead of `require-dev`. It will be installed in production, potentially exposing debug information.",
                    file: 'composer.json',
                    line: $this->findPackageLine($ctx, $package),
                    symbol: $package,
                    snippet: "\"{$package}\": \"{$require[$package]}\"",
                    remediation: "Move {$package} to `require-dev` in composer.json: `composer require --dev {$package}`",
                );
            }
        }
    }

    private function findPackageLine(Context $ctx, string $package): int
    {
        $contents = $ctx->fileContents('composer.json');
        if ($contents === null) {
            return 0;
        }

        $lines = explode("\n", $contents);
        foreach ($lines as $i => $line) {
            if (str_contains($line, '"'.$package.'"')) {
                return $i + 1;
            }
        }

        return 0;
    }
}
