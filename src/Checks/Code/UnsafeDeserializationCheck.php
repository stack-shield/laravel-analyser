<?php

namespace Stackshield\Scanner\Checks\Code;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class UnsafeDeserializationCheck implements Check
{
    public function id(): string
    {
        return 'SS043';
    }

    public function name(): string
    {
        return 'Unsafe Deserialization';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function category(): Category
    {
        return Category::Code;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        foreach ($ctx->phpFiles('app') as $file) {
            $contents = $ctx->fileContents($file);
            if ($contents === null) {
                continue;
            }

            $lines = explode("\n", $contents);

            foreach ($lines as $lineNum => $line) {
                $trimmed = trim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*')) {
                    continue;
                }

                if (! preg_match('/\bunserialize\s*\(/', $line)) {
                    continue;
                }

                // Check if user-controlled data is passed to unserialize
                $hasUserInput = preg_match('/\bunserialize\s*\(\s*\$(?:request|_GET|_POST|_REQUEST|_COOKIE)/', $line)
                    || preg_match('/\bunserialize\s*\(\s*request\s*\(/', $line)
                    || preg_match('/\bunserialize\s*\(\s*\$request\s*->/', $line);

                // Check if allowed_classes option is missing
                $hasAllowedClasses = preg_match('/\bunserialize\s*\([^)]*[\'"]allowed_classes[\'"]\s*/', $line);

                if ($hasUserInput) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: 'unserialize() called with user-controlled data. This can lead to remote code execution via PHP object injection.',
                        file: $file,
                        line: $lineNum + 1,
                        symbol: 'unserialize',
                        snippet: trim($line),
                        remediation: 'Never unserialize user-controlled data. Use json_decode() instead, or validate and sanitize input before deserialization.',
                    );
                } elseif (! $hasAllowedClasses) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: 'unserialize() called without allowed_classes option. This permits instantiation of arbitrary classes, which can lead to object injection attacks.',
                        file: $file,
                        line: $lineNum + 1,
                        symbol: 'unserialize',
                        snippet: trim($line),
                        remediation: "Use unserialize(\$data, ['allowed_classes' => false]) or specify an explicit list of allowed classes. Prefer json_decode() when possible.",
                    );
                }
            }
        }
    }
}
