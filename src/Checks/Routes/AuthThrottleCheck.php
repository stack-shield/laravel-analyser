<?php

namespace StackShield\Analyser\Checks\Routes;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class AuthThrottleCheck implements Check
{
    private const AUTH_PATTERNS = [
        'login', 'signin', 'sign-in',
        'register', 'signup', 'sign-up',
        'password/reset', 'password/email', 'forgot-password',
        'two-factor', '2fa', 'verify',
    ];

    public function id(): string
    {
        return 'SS004';
    }

    public function name(): string
    {
        return 'Auth Routes Without Throttle';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function category(): Category
    {
        return Category::Routes;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        // Parse route files for auth-like routes without throttle middleware
        $routeFiles = ['routes/web.php', 'routes/auth.php', 'routes/api.php'];

        foreach ($routeFiles as $routeFile) {
            $stmts = $ctx->ast($routeFile);
            if (empty($stmts)) {
                continue;
            }

            $nodeFinder = new NodeFinder;
            $methodCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\MethodCall::class);
            $staticCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\StaticCall::class);

            $routeCalls = $this->findRouteCalls($methodCalls, $staticCalls);

            foreach ($routeCalls as $routeCall) {
                $uri = $this->extractUri($routeCall);
                if ($uri === null) {
                    continue;
                }

                if (! $this->isAuthRoute($uri)) {
                    continue;
                }

                if (! $this->hasThrottleMiddleware($routeCall, $stmts)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: "Auth route '{$uri}' does not have throttle middleware. This makes it vulnerable to brute force attacks.",
                        file: $routeFile,
                        line: $routeCall->getStartLine(),
                        symbol: $uri,
                        remediation: "Add throttle middleware: ->middleware('throttle:5,1')",
                    );
                }
            }
        }
    }

    private function findRouteCalls(array $methodCalls, array $staticCalls): array
    {
        $routes = [];

        foreach ($staticCalls as $call) {
            if (! $call->class instanceof Node\Name) {
                continue;
            }
            $className = $call->class->toString();
            if (! in_array($className, ['Route', 'Illuminate\\Support\\Facades\\Route'], true)) {
                continue;
            }
            $method = $call->name instanceof Node\Identifier ? $call->name->toString() : null;
            if (in_array($method, ['post', 'put', 'patch', 'get', 'any'], true)) {
                $routes[] = $call;
            }
        }

        return $routes;
    }

    private function extractUri(Node\Expr $call): ?string
    {
        $args = $call->args ?? [];
        if (empty($args)) {
            return null;
        }

        $firstArg = $args[0]->value ?? null;
        if ($firstArg instanceof Node\Scalar\String_) {
            return $firstArg->value;
        }

        return null;
    }

    private function isAuthRoute(string $uri): bool
    {
        $uri = strtolower(trim($uri, '/'));

        foreach (self::AUTH_PATTERNS as $pattern) {
            if (str_contains($uri, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private function hasThrottleMiddleware(Node\Expr $routeCall, array $stmts): bool
    {
        $nodeFinder = new NodeFinder;
        $allMethodCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\MethodCall::class);

        foreach ($allMethodCalls as $call) {
            if (! ($call->name instanceof Node\Identifier)) {
                continue;
            }

            if ($call->name->toString() !== 'middleware') {
                continue;
            }

            if (! $this->isChainedOn($call, $routeCall)) {
                continue;
            }

            foreach ($call->args as $arg) {
                $value = $arg->value ?? null;
                if ($value instanceof Node\Scalar\String_ && str_starts_with($value->value, 'throttle')) {
                    return true;
                }
                if ($value instanceof Node\Expr\Array_) {
                    foreach ($value->items as $item) {
                        if ($item->value instanceof Node\Scalar\String_ && str_starts_with($item->value->value, 'throttle')) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    private function isChainedOn(Node\Expr\MethodCall $call, Node\Expr $target): bool
    {
        $current = $call->var;
        while ($current !== null) {
            if ($current === $target) {
                return true;
            }
            if ($current instanceof Node\Expr\MethodCall) {
                $current = $current->var;
            } else {
                break;
            }
        }

        return $current === $target;
    }
}
