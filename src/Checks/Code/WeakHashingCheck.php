<?php

namespace StackShield\Analyser\Checks\Code;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class WeakHashingCheck implements Check
{
    /**
     * md5($password) alone is not proof: APR1 htpasswd hashing and breach
     * lookups need MD5 or SHA-1 by design. The finding is a weak hash becoming
     * the stored password or the value a password is checked against.
     */
    private const PATTERNS = [
        '/[\'"]password[\'"]\s*=>\s*md5\s*\(/i' => 'md5() assigned to password field',
        '/[\'"]password[\'"]\s*=>\s*sha1\s*\(/i' => 'sha1() assigned to password field',
        '/->password\s*={1,3}\s*(?:md5|sha1)\s*\(/i' => 'md5() or sha1() used for a stored password',
        '/(?:md5|sha1)\s*\([^)]*\)\s*={2,3}\s*\$\w+->password\b/i' => 'md5() or sha1() used to verify a password',
    ];

    public function id(): string
    {
        return 'SS042';
    }

    public function name(): string
    {
        return 'Weak Hashing for Passwords';
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
        foreach ($ctx->phpFiles('app') as $file) {
            $contents = $ctx->fileContents($file);
            if ($contents === null) {
                continue;
            }

            // Have I Been Pwned's range API takes a SHA-1 prefix by design.
            if (preg_match('/pwnedpasswords|haveibeenpwned/i', $contents)) {
                continue;
            }

            $lines = explode("\n", $contents);

            foreach ($lines as $lineNum => $line) {
                $trimmed = trim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*')) {
                    continue;
                }

                foreach (self::PATTERNS as $pattern => $description) {
                    if (preg_match($pattern, $line)) {
                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $this->severity(),
                            category: $this->category(),
                            message: "{$description}. MD5 and SHA1 are cryptographically weak and unsuitable for password hashing.",
                            file: $file,
                            line: $lineNum + 1,
                            snippet: trim($line),
                            remediation: 'Use Hash::make() or bcrypt() for password hashing, and Hash::check() for verification.',
                        );

                        break; // One finding per line
                    }
                }
            }
        }
    }
}
