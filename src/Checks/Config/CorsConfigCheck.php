<?php

namespace StackShield\Analyser\Checks\Config;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class CorsConfigCheck implements Check
{
    public function id(): string
    {
        return 'SS016';
    }

    public function name(): string
    {
        return 'Permissive CORS Configuration';
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
        $corsConfig = $ctx->fileContents('config/cors.php');
        if ($corsConfig === null) {
            return;
        }

        // Check for wildcard allowed_origins
        if (preg_match("/['\"]allowed_origins['\"]\\s*=>\\s*\\[\\s*['\"]\\*['\"]/", $corsConfig)) {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: "CORS allowed_origins is set to '*'. Any domain can make cross-origin requests to your API.",
                file: 'config/cors.php',
                symbol: 'cors.allowed_origins',
                remediation: 'Restrict allowed_origins to specific trusted domains instead of using wildcard.',
            );
        }

        // Check supports_credentials with wildcard origins
        if (preg_match("/['\"]supports_credentials['\"]\\s*=>\\s*true/", $corsConfig)
            && preg_match("/['\"]allowed_origins['\"]\\s*=>\\s*\\[\\s*['\"]\\*['\"]/", $corsConfig)) {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: Severity::High,
                category: $this->category(),
                message: 'CORS is configured with supports_credentials=true and wildcard origins. This allows any domain to make authenticated cross-origin requests.',
                file: 'config/cors.php',
                symbol: 'cors.supports_credentials',
                remediation: 'Never use wildcard origins with supports_credentials. Specify exact trusted domains.',
            );
        }
    }
}
