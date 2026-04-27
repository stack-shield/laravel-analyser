<?php

namespace Stackshield\Scanner\Checks\Dependencies;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class KnownAdvisoriesCheck implements Check
{
    private const CACHE_DIR = '.stackshield/cache';

    private const CACHE_FILE = 'advisories.json';

    private const CACHE_TTL = 604800; // 7 days

    public function id(): string
    {
        return 'SS030';
    }

    public function name(): string
    {
        return 'Known Security Advisories';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
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

        if (empty($packages)) {
            return;
        }

        $advisories = $this->loadAdvisories($ctx);

        foreach ($packages as $package) {
            $name = $package['name'] ?? '';
            $version = $package['version'] ?? '';

            if (! $name || ! $version) {
                continue;
            }

            $packageAdvisories = $advisories[$name] ?? [];

            foreach ($packageAdvisories as $advisory) {
                if ($this->isAffected($version, $advisory)) {
                    $ghsaId = $advisory['ghsa_id'] ?? $advisory['id'] ?? 'unknown';
                    $title = $advisory['title'] ?? 'Security advisory';
                    $severityStr = strtolower($advisory['severity'] ?? 'high');
                    $fixedVersion = $advisory['patched_versions'] ?? $advisory['fixed_version'] ?? 'unknown';

                    $severity = match ($severityStr) {
                        'critical' => Severity::Critical,
                        'high' => Severity::High,
                        'moderate', 'medium' => Severity::Medium,
                        'low' => Severity::Low,
                        default => Severity::High,
                    };

                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $severity,
                        category: $this->category(),
                        message: "Package {$name}@{$version} has a known vulnerability: {$title} ({$ghsaId})",
                        file: 'composer.lock',
                        symbol: $name,
                        snippet: "\"{$name}\": \"{$version}\"",
                        remediation: is_string($fixedVersion)
                            ? "Update to {$fixedVersion}: composer update {$name}"
                            : "Run composer update {$name} to get the latest patched version.",
                    );
                }
            }
        }
    }

    private function loadAdvisories(Context $ctx): array
    {
        $cacheDir = $ctx->resolve(self::CACHE_DIR);
        $cachePath = $cacheDir.'/'.self::CACHE_FILE;

        if (file_exists($cachePath) && (time() - filemtime($cachePath)) < self::CACHE_TTL) {
            $data = json_decode(file_get_contents($cachePath), true);
            if (is_array($data)) {
                return $data;
            }
        }

        // Fetch from Packagist security advisories API (no auth needed)
        $advisories = $this->fetchAdvisories($ctx);

        if (! empty($advisories)) {
            if (! is_dir($cacheDir)) {
                mkdir($cacheDir, 0755, true);
            }
            file_put_contents($cachePath, json_encode($advisories));
        }

        return $advisories;
    }

    private function fetchAdvisories(Context $ctx): array
    {
        $lock = $ctx->composerLock();
        $packages = array_merge(
            $lock['packages'] ?? [],
            $lock['packages-dev'] ?? []
        );

        $packageNames = array_map(fn ($p) => $p['name'] ?? '', $packages);
        $packageNames = array_filter($packageNames);

        if (empty($packageNames)) {
            return [];
        }

        // Use Packagist security advisories API
        $url = 'https://packagist.org/api/security-advisories/?packages='.implode('&packages=', array_map('urlencode', $packageNames));

        $context = stream_context_create([
            'http' => [
                'timeout' => 30,
                'header' => 'User-Agent: stackshield-scanner/1.0',
            ],
        ]);

        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            return [];
        }

        $data = json_decode($response, true);

        return $data['advisories'] ?? [];
    }

    private function isAffected(string $version, array $advisory): bool
    {
        // Simple version range check
        $affectedVersions = $advisory['affected_versions'] ?? $advisory['affectedVersions'] ?? '';

        if (empty($affectedVersions)) {
            return true; // If no range specified, assume affected
        }

        // Normalize version
        $version = ltrim($version, 'v');

        // Try simple constraint matching
        if (is_string($affectedVersions)) {
            $constraints = explode('|', $affectedVersions);
            foreach ($constraints as $constraint) {
                $constraint = trim($constraint);
                if ($this->matchesConstraint($version, $constraint)) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    private function matchesConstraint(string $version, string $constraint): bool
    {
        // Handle simple constraints like >=1.0,<2.0
        $parts = preg_split('/\s*,\s*/', $constraint);

        foreach ($parts as $part) {
            $part = trim($part);
            if (empty($part)) {
                continue;
            }

            if (preg_match('/^([<>=!]+)\s*(.+)$/', $part, $matches)) {
                $operator = $matches[1];
                $constraintVersion = ltrim($matches[2], 'v');

                if (! version_compare($version, $constraintVersion, $operator)) {
                    return false;
                }
            }
        }

        return true;
    }
}
