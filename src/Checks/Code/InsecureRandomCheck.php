<?php

namespace StackShield\Analyser\Checks\Code;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class InsecureRandomCheck implements Check
{
    private const INSECURE_FUNCTIONS = ['rand', 'mt_rand', 'array_rand'];

    private const SENSITIVE_KEYWORDS = ['token', 'password', 'reset', 'otp', 'secret', 'verify'];

    public function id(): string
    {
        return 'SS040';
    }

    public function name(): string
    {
        return 'Insecure Random Number Generation';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
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

            // Check if the file/context is security-sensitive
            $lowerContents = strtolower($contents);
            $isSensitiveFile = false;
            foreach (self::SENSITIVE_KEYWORDS as $keyword) {
                if (str_contains($lowerContents, $keyword)) {
                    $isSensitiveFile = true;
                    break;
                }
            }

            if (! $isSensitiveFile) {
                continue;
            }

            $lines = explode("\n", $contents);

            foreach ($lines as $lineNum => $line) {
                $trimmed = trim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*')) {
                    continue;
                }

                foreach (self::INSECURE_FUNCTIONS as $func) {
                    if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/', $line)) {
                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $this->severity(),
                            category: $this->category(),
                            message: "Use of {$func}() in a security-sensitive context. This function does not produce cryptographically secure random values.",
                            file: $file,
                            line: $lineNum + 1,
                            symbol: $func,
                            snippet: trim($line),
                            remediation: 'Use random_int() or Str::random() for generating tokens, passwords, OTPs, or other security-sensitive random values.',
                        );

                        break; // One finding per line
                    }
                }
            }
        }
    }
}
