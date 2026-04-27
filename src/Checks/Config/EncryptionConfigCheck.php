<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class EncryptionConfigCheck implements Check
{
    public function id(): string
    {
        return 'SS011';
    }

    public function name(): string
    {
        return 'Weak Encryption Configuration';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $appConfig = $ctx->fileContents('config/app.php');
        if ($appConfig === null) {
            return;
        }

        // Check for weak cipher
        if (preg_match("/['\"]cipher['\"]\\s*=>\\s*['\"](?!AES-256-CBC|aes-256-cbc|AES-256-GCM|aes-256-gcm)([^'\"]+)['\"]/", $appConfig, $matches)) {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: "Encryption cipher is set to '{$matches[1]}' instead of AES-256-CBC or AES-256-GCM.",
                file: 'config/app.php',
                symbol: 'app.cipher',
                remediation: "Use 'AES-256-CBC' cipher (Laravel default) in config/app.php.",
            );
        }
    }
}
