<?php

namespace StackShield\Analyser\Checks\Routes;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class CsrfExemptionCheck implements Check
{
    public function id(): string
    {
        return 'SS006';
    }

    public function name(): string
    {
        return 'CSRF Exemptions on State-Changing Routes';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function category(): Category
    {
        return Category::Routes;
    }

    public function version(): int
    {
        return 2;
    }

    public function run(Context $ctx): iterable
    {
        // Check VerifyCsrfToken middleware for $except
        $middlewarePaths = [
            'app/Http/Middleware/VerifyCsrfToken.php',
        ];

        foreach ($middlewarePaths as $path) {
            $stmts = $ctx->ast($path);
            if (empty($stmts)) {
                continue;
            }

            $nodeFinder = new NodeFinder;
            $classes = $nodeFinder->findInstanceOf($stmts, Node\Stmt\Class_::class);

            foreach ($classes as $class) {
                foreach ($class->stmts as $stmt) {
                    if (! ($stmt instanceof Node\Stmt\Property)) {
                        continue;
                    }

                    foreach ($stmt->props as $prop) {
                        if ($prop->name->toString() !== 'except') {
                            continue;
                        }

                        if ($prop->default instanceof Node\Expr\Array_) {
                            foreach ($prop->default->items as $item) {
                                if ($item->value instanceof Node\Scalar\String_) {
                                    $exemptedUri = $item->value->value;
                                    if ($this->isExternalCallback($exemptedUri)) {
                                        continue;
                                    }

                                    // Flag broad exemptions
                                    if ($this->isBroadExemption($exemptedUri)) {
                                        yield new Finding(
                                            checkId: $this->id(),
                                            checkName: $this->name(),
                                            checkVersion: $this->version(),
                                            severity: Severity::High,
                                            category: $this->category(),
                                            message: "Broad CSRF exemption pattern '{$exemptedUri}' disables CSRF protection for multiple routes. This enables cross-site request forgery attacks.",
                                            file: $path,
                                            line: $item->getStartLine(),
                                            symbol: 'VerifyCsrfToken::$except',
                                            snippet: "'{$exemptedUri}'",
                                            remediation: 'Narrow the CSRF exemption to specific webhook endpoints that genuinely need it, and verify requests using webhook signatures instead.',
                                            advisory: ! $this->isBlanketExemption($exemptedUri),
                                        );
                                    } else {
                                        yield new Finding(
                                            checkId: $this->id(),
                                            checkName: $this->name(),
                                            checkVersion: $this->version(),
                                            severity: $this->severity(),
                                            category: $this->category(),
                                            message: "Route '{$exemptedUri}' is exempt from CSRF verification. Ensure this is intentional and the route validates requests through an alternative mechanism (e.g., webhook signatures).",
                                            file: $path,
                                            line: $item->getStartLine(),
                                            symbol: 'VerifyCsrfToken::$except',
                                            snippet: "'{$exemptedUri}'",
                                            remediation: 'If this route handles webhooks, verify requests using the provider\'s webhook signature. If it\'s a regular form endpoint, remove the CSRF exemption.',
                                            advisory: true,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Laravel 11+ uses bootstrap/app.php for CSRF exceptions
        $bootstrapApp = $ctx->fileContents('bootstrap/app.php');
        if ($bootstrapApp !== null && str_contains($bootstrapApp, 'validateCsrfTokens')) {
            // Check for except patterns
            if (preg_match_all("/except:\s*\[([^\]]+)\]/s", $bootstrapApp, $matches)) {
                foreach ($matches[1] as $exceptBlock) {
                    preg_match_all("/['\"]([^'\"]+)['\"]/", $exceptBlock, $uriMatches);
                    foreach ($uriMatches[1] as $uri) {
                        if ($this->isExternalCallback($uri)) {
                            continue;
                        }
                        $severity = $this->isBroadExemption($uri) ? Severity::High : $this->severity();
                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $severity,
                            category: $this->category(),
                            message: "Route '{$uri}' is exempt from CSRF verification in bootstrap/app.php.",
                            file: 'bootstrap/app.php',
                            symbol: 'validateCsrfTokens',
                            snippet: $uri,
                            remediation: 'Verify requests using webhook signatures or other authentication mechanisms.',
                            advisory: ! $this->isBlanketExemption($uri),
                        );
                    }
                }
            }
        }
    }

    /**
     * Endpoints called by other servers (payment webhooks, OAuth and SAML
     * callbacks, health checks) cannot send a CSRF token; exempting them is
     * correct.
     */
    private function isExternalCallback(string $uri): bool
    {
        return (bool) preg_match('/webhook|hook|stripe|paypal|mollie|paddle|braintree|ipn|callback|oauth|saml|sso|notify|health|cron|pusher|broadcasting/i', $uri);
    }

    /**
     * Only an exemption covering every route is graded. A wildcard over one
     * area ('remote/*', '/dav/*') usually serves a non-browser client
     * authenticated another way, which static analysis cannot confirm.
     */
    private function isBlanketExemption(string $uri): bool
    {
        return trim($uri, '/ ') === '*';
    }

    private function isBroadExemption(string $uri): bool
    {
        return str_contains($uri, '*') || str_contains($uri, 'api/*') || $uri === '*';
    }
}
