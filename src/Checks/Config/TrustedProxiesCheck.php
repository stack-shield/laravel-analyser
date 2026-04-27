<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class TrustedProxiesCheck implements Check
{
    public function id(): string
    {
        return 'SS045';
    }

    public function name(): string
    {
        return 'Trusted Proxies Wildcard';
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
        // Check Laravel 10 and earlier: app/Http/Middleware/TrustProxies.php
        $middlewareFile = 'app/Http/Middleware/TrustProxies.php';
        $contents = $ctx->fileContents($middlewareFile);

        if ($contents !== null) {
            $lines = explode("\n", $contents);

            foreach ($lines as $lineNum => $line) {
                if (preg_match('/protected\s+\$proxies\s*=\s*[\'\"]\*[\'\"]/', $line)
                    || preg_match('/protected\s+\$proxies\s*=\s*\'\*\'/', $line)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: 'TrustProxies middleware is configured to trust all proxies (\'*\'). This allows any IP to spoof headers like X-Forwarded-For, bypassing IP-based security controls.',
                        file: $middlewareFile,
                        line: $lineNum + 1,
                        symbol: 'TrustProxies::$proxies',
                        snippet: trim($line),
                        remediation: 'Set $proxies to the specific IP addresses of your trusted load balancers or reverse proxies instead of \'*\'.',
                    );

                    break;
                }
            }
        }

        // Check Laravel 11+: bootstrap/app.php
        $bootstrapFile = 'bootstrap/app.php';
        $bootstrapContents = $ctx->fileContents($bootstrapFile);

        if ($bootstrapContents !== null) {
            $lines = explode("\n", $bootstrapContents);

            foreach ($lines as $lineNum => $line) {
                if (preg_match('/trustProxies\s*\(\s*at\s*:\s*[\'\"]\*[\'\"]/', $line)
                    || preg_match('/trustProxies\s*\([^)]*[\'\"]\*[\'\"]/', $line)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: 'TrustProxies is configured to trust all proxies (\'*\') in bootstrap/app.php. This allows any IP to spoof headers like X-Forwarded-For.',
                        file: $bootstrapFile,
                        line: $lineNum + 1,
                        symbol: 'trustProxies',
                        snippet: trim($line),
                        remediation: 'Specify the exact IP addresses of your trusted proxies instead of \'*\'.',
                    );

                    break;
                }
            }
        }
    }
}
