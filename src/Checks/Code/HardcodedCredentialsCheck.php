<?php

namespace Stackshield\Scanner\Checks\Code;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class HardcodedCredentialsCheck implements Check
{
    private const PATTERNS = [
        '/(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']/i' => 'Hardcoded password',
        '/(?:api[_-]?key|apikey)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']/i' => 'Hardcoded API key',
        '/(?:secret[_-]?key|secret)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']/i' => 'Hardcoded secret key',
        '/(?:access[_-]?token)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']/i' => 'Hardcoded access token',
        '/(?:AKIA[0-9A-Z]{16})/i' => 'AWS access key ID',
        '/(?:sk[_-]live[_-][a-zA-Z0-9]{24,})/i' => 'Stripe secret key',
    ];

    public function id(): string
    {
        return 'SS008';
    }

    public function name(): string
    {
        return 'Hardcoded Credentials';
    }

    public function severity(): Severity
    {
        return Severity::High;
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
        $scanPaths = ['app', 'config', 'routes'];

        foreach ($scanPaths as $path) {
            foreach ($ctx->phpFiles($path) as $file) {
                $contents = $ctx->fileContents($file);
                if ($contents === null) {
                    continue;
                }

                $lines = explode("\n", $contents);

                foreach ($lines as $lineNum => $line) {
                    // Skip comments
                    $trimmed = trim($line);
                    if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*')) {
                        continue;
                    }

                    // Skip env() calls (proper pattern)
                    if (str_contains($line, 'env(')) {
                        continue;
                    }

                    // Skip config() calls
                    if (str_contains($line, 'config(')) {
                        continue;
                    }

                    foreach (self::PATTERNS as $pattern => $description) {
                        if (preg_match($pattern, $line, $matches)) {
                            yield new Finding(
                                checkId: $this->id(),
                                checkName: $this->name(),
                                checkVersion: $this->version(),
                                severity: $this->severity(),
                                category: $this->category(),
                                message: "{$description} detected in source code.",
                                file: $file,
                                line: $lineNum + 1,
                                snippet: $this->redactMatch($matches[0]),
                                remediation: 'Move credentials to environment variables and reference them with env().',
                            );

                            break; // One finding per line
                        }
                    }
                }
            }
        }
    }

    private function redactMatch(string $match): string
    {
        // Redact the actual secret value
        return preg_replace('/["\'][^"\']+["\']/', '"***REDACTED***"', $match) ?? $match;
    }
}
