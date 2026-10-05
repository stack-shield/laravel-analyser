<?php

namespace StackShield\Analyser\Checks\Code;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

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
        return 2;
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

                    // Enum cases name things; they do not hold secrets.
                    if (str_starts_with($trimmed, 'case ')) {
                        continue;
                    }

                    foreach (self::PATTERNS as $pattern => $description) {
                        if (preg_match($pattern, $line, $matches) && ! $this->isPlaceholder($matches[0])) {
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

    /**
     * The quoted value names a field, route or label rather than being a
     * secret: 'current_password', '/forgot-password', 'database.view-password',
     * a string built from variables, or a marker like '*** NO PASSWORD ***'.
     */
    private function isPlaceholder(string $match): bool
    {
        if (! preg_match('/["\']([^"\']*)["\']\s*$/', $match, $value)) {
            return false;
        }
        $value = $value[1];

        return (bool) preg_match('/pass|pwd|secret|token|key/i', $value)
            || str_starts_with($value, '/')
            || str_starts_with($value, '.')
            || str_contains($value, '$')
            || str_contains($value, '***');
    }

    private function redactMatch(string $match): string
    {
        // Redact the actual secret value
        return preg_replace('/["\'][^"\']+["\']/', '"***REDACTED***"', $match) ?? $match;
    }
}
