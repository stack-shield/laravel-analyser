<?php

namespace Stackshield\Scanner\Baseline;

use Stackshield\Scanner\Finding;
use Stackshield\Scanner\Scanner;
use Symfony\Component\Yaml\Yaml;

final class Baseline
{
    /** @var array<string, array> Fingerprint => finding data */
    private array $entries = [];

    public function __construct(array $entries = [])
    {
        foreach ($entries as $entry) {
            $this->entries[$entry['fingerprint']] = $entry;
        }
    }

    public static function fromFile(string $path): self
    {
        if (! file_exists($path)) {
            return new self;
        }

        $data = Yaml::parseFile($path);
        if (! is_array($data) || ! isset($data['findings'])) {
            return new self;
        }

        return new self($data['findings']);
    }

    public function isSuppressed(Finding $finding): bool
    {
        if (! isset($this->entries[$finding->fingerprint])) {
            return false;
        }

        $entry = $this->entries[$finding->fingerprint];

        // If check version has been bumped, don't suppress
        return ($entry['check_version'] ?? 0) >= $finding->checkVersion;
    }

    /** @param Finding[] $findings */
    public static function generate(array $findings): array
    {
        return [
            'version' => 1,
            'generated_at' => date('c'),
            'generator' => 'stackshield-scanner@'.Scanner::VERSION,
            'findings' => array_map(fn (Finding $f) => [
                'fingerprint' => $f->fingerprint,
                'check' => $f->checkId,
                'check_version' => $f->checkVersion,
                'file' => $f->file,
                'symbol' => $f->symbol,
                'first_seen' => date('Y-m-d'),
                'note' => null,
            ], $findings),
        ];
    }

    public static function write(string $path, array $findings): void
    {
        $data = self::generate($findings);
        $yaml = Yaml::dump($data, 4, 2);
        file_put_contents($path, $yaml);
    }

    public function entries(): array
    {
        return $this->entries;
    }

    public function count(): int
    {
        return count($this->entries);
    }
}
