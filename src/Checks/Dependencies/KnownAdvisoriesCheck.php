<?php

namespace StackShield\Analyser\Checks\Dependencies;

use Composer\Semver\Semver;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class KnownAdvisoriesCheck implements Check
{
    private const CACHE_TTL = 86400;

    private const API = 'https://packagist.org/api/security-advisories/';

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
        return 2;
    }

    /**
     * Installed versions from composer.lock against Packagist's advisory
     * database, the same source composer audit uses. Advisories in
     * require-dev packages are advisory: they do not ship to production.
     */
    public function run(Context $ctx): iterable
    {
        if ($ctx->config()['offline'] ?? false) {
            return;
        }

        $lock = $ctx->composerLock();
        $installed = [];
        foreach (['packages' => false, 'packages-dev' => true] as $section => $dev) {
            foreach ($lock[$section] ?? [] as $package) {
                $name = $package['name'] ?? '';
                $version = ltrim($package['version'] ?? '', 'v');
                // Branch checkouts (dev-main) have no version to compare.
                if ($name !== '' && $version !== '' && ! str_starts_with($version, 'dev-')) {
                    $installed[$name] = ['version' => $version, 'dev' => $dev];
                }
            }
        }

        if ($installed === []) {
            return;
        }

        $advisories = $this->advisories(array_keys($installed), $ctx->config()['advisory_cache_dir'] ?? null);

        // One finding per vulnerable package: an outdated dependency is one
        // problem to fix, however many advisories it has collected.
        foreach ($installed as $name => ['version' => $version, 'dev' => $dev]) {
            $affecting = array_values(array_filter(
                $advisories[$name] ?? [],
                fn (array $advisory) => $this->isAffected($version, $advisory['affectedVersions'] ?? ''),
            ));

            if ($affecting === []) {
                continue;
            }

            $severities = array_map(fn (array $advisory) => $this->mapSeverity($advisory['severity'] ?? null), $affecting);
            usort($severities, fn (Severity $x, Severity $y) => $y->weight() <=> $x->weight());
            $ids = array_map(fn (array $advisory) => $advisory['cve'] ?? $advisory['advisoryId'] ?? 'unknown', $affecting);
            $summary = count($affecting) === 1
                ? ($affecting[0]['title'] ?? 'Security advisory')." ({$ids[0]})"
                : count($affecting).' known vulnerabilities ('.implode(', ', array_slice($ids, 0, 5)).(count($ids) > 5 ? ', ...' : '').')';

            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $severities[0],
                category: $this->category(),
                message: "{$name} {$version} is affected by {$summary}.".($dev ? ' It is a development dependency, so it does not ship to production.' : ''),
                file: 'composer.lock',
                symbol: $name,
                snippet: "\"{$name}\": \"{$version}\"",
                remediation: "Update {$name} to a patched version: composer update {$name}",
                advisory: $dev,
            );
        }
    }

    /**
     * Packagist rates many older advisories with no severity. Unrated is
     * graded as medium rather than assumed high.
     */
    private function mapSeverity(?string $severity): Severity
    {
        return match (strtolower((string) $severity)) {
            'critical' => Severity::Critical,
            'high' => Severity::High,
            'low' => Severity::Low,
            default => Severity::Medium,
        };
    }

    private function isAffected(string $version, string $affectedVersions): bool
    {
        if ($affectedVersions === '') {
            return false;
        }

        try {
            return Semver::satisfies($version, $affectedVersions);
        } catch (\UnexpectedValueException) {
            return false;
        }
    }

    /**
     * @param  string[]  $packages
     * @return array<string, array<int, array<string, mixed>>>
     */
    private function advisories(array $packages, ?string $cacheDir): array
    {
        sort($packages);
        $cacheDir ??= sys_get_temp_dir().'/stackshield-analyser';
        $cachePath = $cacheDir.'/advisories-'.sha1(implode(',', $packages)).'.json';

        if (is_file($cachePath) && time() - filemtime($cachePath) < self::CACHE_TTL) {
            $cached = json_decode((string) file_get_contents($cachePath), true);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $body = implode('&', array_map(fn ($p) => 'packages[]='.urlencode($p), $packages));
        $response = @file_get_contents(self::API, false, stream_context_create(['http' => [
            'method' => 'POST',
            'timeout' => 30,
            'header' => "Content-Type: application/x-www-form-urlencoded\r\nUser-Agent: stackshield-laravel-analyser",
            'content' => $body,
        ]]));

        $advisories = json_decode((string) $response, true)['advisories'] ?? null;
        if (! is_array($advisories)) {
            return [];
        }

        if (! is_dir($cacheDir)) {
            @mkdir($cacheDir, 0755, true);
        }
        @file_put_contents($cachePath, json_encode($advisories));

        return $advisories;
    }
}
