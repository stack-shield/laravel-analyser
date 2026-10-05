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
    /**
     * Endpoints that accept a guessable secret or send mail on request. Routes
     * such as register or email/verify/{id}/{hash} (a signed link) are not
     * brute-force targets.
     */
    private const AUTH_PATTERNS = [
        'login', 'signin', 'sign-in',
        'password/reset', 'password/email', 'forgot-password', 'reset-password',
        'two-factor', '2fa', 'mfa', 'otp',
    ];

    /** Signs that an app throttles login attempts in code rather than route middleware. */
    private const CODE_THROTTLE_SIGNALS = [
        'ThrottlesLogins', 'ensureIsNotRateLimited', 'RateLimiter::tooManyAttempts',
        'RateLimiter::attempt', 'RateLimiter::hit', "->middleware('throttle", '->middleware("throttle',
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
        return 2;
    }

    public function run(Context $ctx): iterable
    {
        $routeFiles = ['routes/web.php', 'routes/auth.php', 'routes/api.php'];
        $throttledInCode = $this->throttlesInCode($ctx);

        foreach ($routeFiles as $routeFile) {
            $stmts = $ctx->ast($routeFile);
            if (empty($stmts)) {
                continue;
            }

            $nodeFinder = new NodeFinder;
            $methodCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\MethodCall::class);
            $staticCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\StaticCall::class);

            $routeCalls = $this->findRouteCalls($methodCalls, $staticCalls);
            $inThrottledGroup = $this->routesInThrottledGroups($methodCalls);

            foreach ($routeCalls as $routeCall) {
                $uri = $this->extractUri($routeCall);
                if ($uri === null || ! $this->isAuthRoute($uri)) {
                    continue;
                }

                if ($throttledInCode
                    || isset($inThrottledGroup[spl_object_id($routeCall)])
                    || $this->hasThrottleMiddleware($routeCall, $stmts)) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "Auth route '{$uri}' accepts submissions without rate limiting: no throttle middleware on the route or its group, and no throttling in the login code. It is open to brute-force attacks.",
                    file: $routeFile,
                    line: $routeCall->getStartLine(),
                    symbol: $uri,
                    remediation: "Add throttle middleware: ->middleware('throttle:5,1'), or rate limit in the controller with RateLimiter::tooManyAttempts().",
                );
            }
        }
    }

    /**
     * Breeze and Jetstream throttle in LoginRequest, Fortify through its login
     * limiter, older apps through ThrottlesLogins or controller middleware.
     */
    private function throttlesInCode(Context $ctx): bool
    {
        $require = $ctx->composerJson()['require'] ?? [];
        if (isset($require['laravel/fortify']) || isset($require['laravel/jetstream'])) {
            return true;
        }

        foreach ($ctx->phpFiles('app') as $file) {
            $contents = $ctx->fileContents($file) ?? '';
            foreach (self::CODE_THROTTLE_SIGNALS as $signal) {
                if (str_contains($contents, $signal)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Route calls declared inside ->group(...) of a chain that applies
     * throttle middleware, keyed by spl_object_id.
     *
     * @param  Node\Expr\MethodCall[]  $methodCalls
     * @return array<int, true>
     */
    private function routesInThrottledGroups(array $methodCalls): array
    {
        $protected = [];
        $nodeFinder = new NodeFinder;

        foreach ($methodCalls as $call) {
            if (! $call->name instanceof Node\Identifier || $call->name->toString() !== 'group') {
                continue;
            }
            if (! $this->chainAppliesThrottle($call->var)) {
                continue;
            }

            foreach ($call->args as $arg) {
                foreach ($nodeFinder->findInstanceOf($arg, Node\Expr\StaticCall::class) as $inner) {
                    $protected[spl_object_id($inner)] = true;
                }
            }
        }

        return $protected;
    }

    private function chainAppliesThrottle(Node\Expr $node): bool
    {
        while ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            $name = $node->name instanceof Node\Identifier ? $node->name->toString() : null;
            if ($name === 'middleware' && $this->argsMentionThrottle($node->args)) {
                return true;
            }
            if ($node instanceof Node\Expr\StaticCall) {
                break;
            }
            $node = $node->var;
        }

        return false;
    }

    private function argsMentionThrottle(array $args): bool
    {
        foreach ($args as $arg) {
            $value = $arg->value ?? null;
            $strings = $value instanceof Node\Expr\Array_
                ? array_map(fn ($item) => $item?->value, $value->items)
                : [$value];
            foreach ($strings as $string) {
                if ($string instanceof Node\Scalar\String_ && str_starts_with($string->value, 'throttle')) {
                    return true;
                }
            }
        }

        return false;
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
            if (in_array($method, ['post', 'put', 'patch', 'any'], true)) {
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
