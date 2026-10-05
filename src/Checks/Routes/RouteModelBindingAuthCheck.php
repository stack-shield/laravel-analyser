<?php

namespace StackShield\Analyser\Checks\Routes;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class RouteModelBindingAuthCheck implements Check
{
    private const USER_SCOPED_PATTERNS = [
        '{user}', '{account}', '{profile}', '{order}', '{invoice}',
        '{subscription}', '{payment}', '{address}', '{card}',
    ];

    public function id(): string
    {
        return 'SS005';
    }

    public function name(): string
    {
        return 'Route Model Binding Without Auth';
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
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $routeFiles = ['routes/web.php', 'routes/api.php'];

        foreach ($routeFiles as $routeFile) {
            $stmts = $ctx->ast($routeFile);
            if (empty($stmts)) {
                continue;
            }

            $nodeFinder = new NodeFinder;
            $staticCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\StaticCall::class);

            foreach ($staticCalls as $call) {
                if (! $call->class instanceof Node\Name) {
                    continue;
                }
                if (! in_array($call->class->toString(), ['Route', 'Illuminate\\Support\\Facades\\Route'], true)) {
                    continue;
                }

                $method = $call->name instanceof Node\Identifier ? $call->name->toString() : null;
                if (! in_array($method, ['get', 'post', 'put', 'patch', 'delete', 'any'], true)) {
                    continue;
                }

                $uri = $this->extractUri($call);
                if ($uri === null) {
                    continue;
                }

                if (! $this->hasUserScopedBinding($uri)) {
                    continue;
                }

                if (! $this->hasAuthMiddleware($call, $stmts)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: "Route '{$uri}' has user-scoped model binding but no auth middleware. Any visitor could access this resource by ID.",
                        file: $routeFile,
                        line: $call->getStartLine(),
                        symbol: $uri,
                        remediation: "Add auth middleware: ->middleware('auth')",
                    );
                }
            }
        }
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

    private function hasUserScopedBinding(string $uri): bool
    {
        foreach (self::USER_SCOPED_PATTERNS as $pattern) {
            if (str_contains($uri, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private function hasAuthMiddleware(Node\Expr $routeCall, array $stmts): bool
    {
        // Walk up the method chain from this route call to find ->middleware('auth')
        $nodeFinder = new NodeFinder;
        $allMethodCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\MethodCall::class);

        // Find method calls that are chained onto this specific route call
        foreach ($allMethodCalls as $call) {
            if (! ($call->name instanceof Node\Identifier)) {
                continue;
            }

            if ($call->name->toString() !== 'middleware') {
                continue;
            }

            // Check if this middleware call is chained onto our route call
            // by walking the var chain to see if it contains our route call
            if (! $this->isChainedOn($call, $routeCall)) {
                continue;
            }

            foreach ($call->args as $arg) {
                $value = $arg->value ?? null;
                if ($value instanceof Node\Scalar\String_) {
                    if (in_array($value->value, ['auth', 'auth:sanctum', 'auth:api', 'auth:web'], true)) {
                        return true;
                    }
                }
                if ($value instanceof Node\Expr\Array_) {
                    foreach ($value->items as $item) {
                        if ($item->value instanceof Node\Scalar\String_) {
                            if (in_array($item->value->value, ['auth', 'auth:sanctum', 'auth:api', 'auth:web'], true)) {
                                return true;
                            }
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
                // Check if the inner call is our target
                if ($current->var === $target) {
                    return true;
                }
                $current = $current->var;
            } else {
                break;
            }
        }

        return $current === $target;
    }
}
