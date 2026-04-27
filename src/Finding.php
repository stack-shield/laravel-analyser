<?php

namespace Stackshield\Scanner;

use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;

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
    ) {
        $this->fingerprint = Baseline\Fingerprint::generate(
            $this->checkId,
            $this->file,
            $this->symbol,
            $this->snippet,
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
        ];
    }
}
