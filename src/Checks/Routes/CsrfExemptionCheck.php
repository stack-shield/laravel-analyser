<?php

namespace StackShield\Analyser\Checks\Routes;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;
use StackShield\Analyser\Routes\Route;
use StackShield\Analyser\Routes\RouteCollector;

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
        return 3;
    }

    /**
     * CSRF protection matters for state-changing routes that trust the session
     * cookie. An exemption is only a vulnerability when it covers such a
     * route: webhooks, daemon APIs with their own tokens, and public forms
     * are exempted correctly.
     */
    public function run(Context $ctx): iterable
    {
        $routes = RouteCollector::routes($ctx);

        foreach ($this->exemptions($ctx) as [$pattern, $file, $line]) {
            if ($this->isExternalCallback($pattern)) {
                continue;
            }

            if (trim($pattern, '/ ') === '*') {
                yield $this->finding(Severity::High, "The CSRF exemption '{$pattern}' disables CSRF protection for every route.", $pattern, $file, $line);

                continue;
            }

            $exposed = array_values(array_filter($routes, fn (Route $route) => ! $route->inGroup('api')
                && $route->isStateChanging()
                && $route->matches($pattern)
                && ($route->hasSessionAuth() || RouteCollector::controllerRequiresAuth($ctx, $route->controller, $route->action))));

            if ($exposed === []) {
                continue;
            }

            $examples = implode(', ', array_map(fn (Route $route) => implode('|', $route->methods).' /'.$route->uri, array_slice($exposed, 0, 3)));

            yield $this->finding(
                str_contains($pattern, '*') ? Severity::High : Severity::Medium,
                "The CSRF exemption '{$pattern}' covers ".count($exposed)." state-changing route(s) authenticated by the session cookie ({$examples}). Another site can submit these on behalf of a logged-in user.",
                $pattern,
                $file,
                $line,
            );
        }
    }

    /**
     * Endpoints called by other servers or API clients (payment webhooks,
     * OAuth token exchange, SAML and OAuth callbacks, health checks) cannot
     * send a CSRF token; exempting them is the documented setup.
     */
    private function isExternalCallback(string $pattern): bool
    {
        return (bool) preg_match('/webhook|hook|stripe|paypal|mollie|paddle|braintree|ipn|callback|oauth|saml|sso|notify|health|cron|pusher/i', $pattern);
    }

    private function finding(Severity $severity, string $message, string $pattern, string $file, int $line): Finding
    {
        return new Finding(
            checkId: $this->id(),
            checkName: $this->name(),
            checkVersion: $this->version(),
            severity: $severity,
            category: $this->category(),
            message: $message,
            file: $file,
            line: $line,
            symbol: 'csrf.except',
            snippet: "'{$pattern}'",
            remediation: 'Remove the exemption so these routes require a CSRF token. Exempt only endpoints called by other servers, and authenticate those with a signature or token instead of the session.',
        );
    }

    /**
     * Patterns from VerifyCsrfToken::$except (Laravel 10 and earlier) and
     * validateCsrfTokens()/preventRequestForgery() except: lists or
     * VerifyCsrfToken::except() calls (11+).
     *
     * @return array<int, array{0: string, 1: string, 2: int}>
     */
    private function exemptions(Context $ctx): array
    {
        $exemptions = [];
        $finder = new NodeFinder;

        foreach ($ctx->phpFiles('app/Http/Middleware') as $file) {
            foreach ($finder->findInstanceOf($ctx->ast($file), Node\PropertyItem::class) as $property) {
                if ($property->name->toString() === 'except' && $property->default instanceof Node\Expr\Array_
                    && preg_match('/Csrf|Forgery/i', $file)) {
                    foreach ($this->strings($property->default) as [$pattern, $line]) {
                        $exemptions[] = [$pattern, $file, $line];
                    }
                }
            }
        }

        $sources = ['bootstrap/app.php', ...iterator_to_array($ctx->phpFiles('app/Providers'), false)];
        foreach ($sources as $file) {
            $calls = $finder->find($ctx->ast($file), fn (Node $node) => ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall)
                && $node->name instanceof Node\Identifier
                && in_array($node->name->toString(), ['validateCsrfTokens', 'preventRequestForgery', 'except'], true));

            foreach ($calls as $call) {
                if ($call->name->toString() === 'except'
                    && ! ($call instanceof Node\Expr\StaticCall && $call->class instanceof Node\Name && preg_match('/Csrf|Forgery/i', $call->class->toString()))) {
                    continue;
                }
                foreach ($call->getRawArgs() as $arg) {
                    if ($arg instanceof Node\Arg && $arg->value instanceof Node\Expr\Array_
                        && ($arg->name === null || $arg->name->toString() === 'except')) {
                        foreach ($this->strings($arg->value) as [$pattern, $line]) {
                            $exemptions[] = [$pattern, $file, $line];
                        }
                    }
                }
            }
        }

        return $exemptions;
    }

    /** @return array<int, array{0: string, 1: int}> */
    private function strings(Node\Expr\Array_ $array): array
    {
        $strings = [];
        foreach (array_filter($array->items) as $item) {
            if ($item->value instanceof Node\Scalar\String_) {
                $strings[] = [$item->value->value, $item->getStartLine()];
            }
        }

        return $strings;
    }
}
