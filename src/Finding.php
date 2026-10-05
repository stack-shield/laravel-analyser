<?php

namespace StackShield\Analyser;

use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;

final class Finding
{
    public readonly string $fingerprint;

    public function __construct(
        public readonly string $checkId,
        public readonly string $checkName,
        public readonly int $checkVersion,
        public readonly Severity $severity,
        public readonly Category $category,
        public readonly string $message,
        public readonly string $file,
        public readonly int $line = 0,
        public readonly ?string $symbol = null,
        public readonly ?string $snippet = null,
        public readonly ?string $remediation = null,
        public readonly bool $advisory = false,
    ) {
        $this->fingerprint = Baseline\Fingerprint::generate(
            $this->checkId,
            $this->file,
            $this->symbol,
            $this->snippet,
        );
    }

    public function asAdvisory(): self
    {
        return new self(
            $this->checkId, $this->checkName, $this->checkVersion, $this->severity,
            $this->category, $this->message, $this->file, $this->line,
            $this->symbol, $this->snippet, $this->remediation, advisory: true,
        );
    }

    public function toArray(): array
    {
        return [
            'check_id' => $this->checkId,
            'check_name' => $this->checkName,
            'check_version' => $this->checkVersion,
            'severity' => $this->severity->value,
            'category' => $this->category->value,
            'message' => $this->message,
            'file' => $this->file,
            'line' => $this->line,
            'symbol' => $this->symbol,
            'snippet' => $this->snippet,
            'fingerprint' => $this->fingerprint,
            'remediation' => $this->remediation,
            'advisory' => $this->advisory,
        ];
    }
}
