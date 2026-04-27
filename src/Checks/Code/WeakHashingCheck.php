<?php

namespace Stackshield\Scanner\Checks\Code;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class WeakHashingCheck implements Check
{
    private const PATTERNS = [
        '/\bmd5\s*\(\s*\$password/i' => 'md5() used for password hashing',
        '/\bsha1\s*\(\s*\$password/i' => 'sha1() used for password hashing',
        '/\bmd5\s*\(\s*\$passwd/i' => 'md5() used for password hashing',
        '/\bsha1\s*\(\s*\$passwd/i' => 'sha1() used for password hashing',
        '/\bmd5\s*\(\s*\$pwd/i' => 'md5() used for password hashing',
        '/\bsha1\s*\(\s*\$pwd/i' => 'sha1() used for password hashing',
        '/\bmd5\s*\(\s*\$secret/i' => 'md5() used for secret hashing',
        '/\bsha1\s*\(\s*\$secret/i' => 'sha1() used for secret hashing',
        '/[\'"]password[\'"]\s*=>\s*md5\s*\(/i' => 'md5() assigned to password field',
        '/[\'"]password[\'"]\s*=>\s*sha1\s*\(/i' => 'sha1() assigned to password field',
        '/md5\s*\([^)]+\)\s*={2,3}\s*/' => 'md5() hash comparison (potential password verification)',
        '/sha1\s*\([^)]+\)\s*={2,3}\s*/' => 'sha1() hash comparison (potential password verification)',
        '/===?\s*md5\s*\(/' => 'Comparison against md5() hash',
        '/===?\s*sha1\s*\(/' => 'Comparison against sha1() hash',
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
