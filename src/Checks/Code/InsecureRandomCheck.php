<?php

namespace StackShield\Analyser\Checks\Code;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class InsecureRandomCheck implements Check
{
    /**
     * The random value has to land in something secret-shaped on the same
     * statement: $token = mt_rand(...), 'otp' => rand(...). A file merely
     * mentioning "token" is not enough; retry jitter, seeders and demo data
     * use rand() legitimately.
     */
    private const SENSITIVE_TARGET = '/(?:\$|[\'"])\w*(?:token|password|passwd|otp|secret|nonce|salt|pin|code|key)\w*[\'"]?\s*(?:=>|=(?!=))[^;]*?\b(?<func>mt_rand|rand)\s*\(/i';

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
        return 2;
    }

    public function run(Context $ctx): iterable
    {
        foreach ($ctx->phpFiles('app') as $file) {
            $contents = $ctx->fileContents($file);
            if ($contents === null) {
                continue;
            }

            foreach (explode("\n", $contents) as $lineNum => $line) {
                $trimmed = trim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*')) {
                    continue;
                }

                if (! preg_match(self::SENSITIVE_TARGET, $line, $match)) {
                    continue;
                }

                $func = $match['func'];

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "{$func}() generates what looks like a secret value. It is not cryptographically secure, so the value can be predicted.",
                    file: $file,
                    line: $lineNum + 1,
                    symbol: $func,
                    snippet: $trimmed,
                    remediation: 'Use random_int() or Str::random() for generating tokens, passwords, OTPs, or other security-sensitive random values.',
                );
            }
        }
    }
}
