<?php

namespace StackShield\Analyser\Routes;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Context;

/**
 * Reads route files the way Laravel registers them: group middleware and
 * prefixes (fluent and array style), files loaded by a group or a require,
 * and routes declared only inside an environment check.
 */
final class RouteCollector
{
    private const VERBS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'match', 'view', 'redirect', 'permanentRedirect'];

    private const RESOURCE = ['resource', 'apiResource'];

    /** Fluent calls that set attributes for the route or group that follows. */
    private const ATTRIBUTES = ['middleware', 'withoutMiddleware', 'prefix', 'name', 'as', 'domain', 'controller', 'namespace', 'where', 'whereNumber', 'whereAlpha', 'whereUuid', 'scopeBindings', 'withoutScopedBindings', 'can'];

    /** @var Route[] */
    private array $routes = [];

    /** @var array<string, true> */
    private array $visited = [];

    private function __construct(private readonly Context $ctx) {}

    /** @return Route[] */
    public static function routes(Context $ctx): array
    {
        return $ctx->remember('routes', function () use ($ctx) {
            $collector = new self($ctx);

            // Route files mapped by a provider or bootstrap/app.php's then:
            // closure get the middleware and prefix given there.
            $collector->collectRegistrations();

            $collector->collectFile('routes/web.php', new GroupState(middleware: ['web']));
            $collector->collectFile('routes/api.php', new GroupState(prefix: 'api', middleware: ['api']));

            foreach (glob($ctx->resolve('routes').'/*.php') ?: [] as $path) {
                $file = $ctx->relativize($path);
                if (! in_array(basename($file), ['console.php', 'channels.php'], true)) {
                    $collector->collectFile($file, new GroupState(middleware: ['web']));
                }
            }

            $middleware = MiddlewareMap::for($ctx);

            return array_map(fn (Route $route) => $route->withExpandedMiddleware($middleware->expand($route->middleware)), $collector->routes);
        });
    }

    /** Behind auth through its middleware or its controller. */
    public static function requiresAuth(Context $ctx, Route $route): bool
    {
        return $route->hasAuthMiddleware() || self::controllerRequiresAuth($ctx, $route->controller, $route->action);
    }

    /**
     * Whether the controller behind a route requires authentication itself:
     * $this->middleware('auth') in its constructor, HasMiddleware, or a
     * #[Middleware('auth')] attribute, on the class or a parent.
     */
    public static function controllerRequiresAuth(Context $ctx, ?string $controller, ?string $action): bool
    {
        for ($depth = 0; $controller !== null && $depth < 4; $depth++) {
            $file = $ctx->classFile($controller);
            if ($file === null) {
                return false;
            }

            foreach (preg_split('/\R/', $ctx->fileContents($file) ?? '') as $line) {
                if (! preg_match('/(?:->middleware\(|new\s+Middleware\(|#\[Middleware\()\s*\[?\s*(?:[\'"](?:auth|can:|role|permission|admin|verified)|(?!RedirectIf|Guest)\w*(?:Authenticate|VerifyAdmins?|IsAdmin)\w*::class)/i', $line)) {
                    continue;
                }
                // ->except(['show']) or except: ['show'] leaves those actions public.
                if ($action !== null && preg_match('/except/i', $line) && preg_match('/[\'"]'.preg_quote($action, '/').'[\'"]/', $line)) {
                    continue;
                }
                if ($action !== null && preg_match('/only/i', $line) && ! preg_match('/[\'"]'.preg_quote($action, '/').'[\'"]/', $line)) {
                    continue;
                }

                return true;
            }

            $class = (new NodeFinder)->findFirstInstanceOf($ctx->ast($file), Node\Stmt\Class_::class);
            $controller = $class?->extends?->toString();
        }

        return false;
    }

    private function collectRegistrations(): void
    {
        $sources = ['bootstrap/app.php'];
        foreach ($this->ctx->phpFiles('app/Providers') as $provider) {
            if (preg_match('/Route::.*group\(|->group\(\s*base_path/s', $this->ctx->fileContents($provider) ?? '')) {
                $sources[] = $provider;
            }
        }

        $finder = new NodeFinder;
        foreach ($sources as $source) {
            $groups = $finder->find($this->ctx->ast($source), fn (Node $node) => $node instanceof Node\Expr\MethodCall
                && $node->name instanceof Node\Identifier && $node->name->toString() === 'group');

            foreach ($groups as $group) {
                $this->collectExpression($group, 'routes/_provider.php', new GroupState);
            }
        }
    }

    private function collectFile(string $file, GroupState $state): void
    {
        if (isset($this->visited[$file]) || ! $this->ctx->fileExists($file)) {
            return;
        }
        $this->visited[$file] = true;

        $this->collectStatements($this->ctx->ast($file), $file, $state);
    }

    /** @param Node\Stmt[] $stmts */
    private function collectStatements(array $stmts, string $file, GroupState $state): void
    {
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Namespace_) {
                $this->collectStatements($stmt->stmts, $file, $state);
            } elseif ($stmt instanceof Node\Stmt\Expression) {
                $this->collectExpression($stmt->expr, $file, $state);
            } elseif ($stmt instanceof Node\Stmt\If_) {
                $guarded = $this->isEnvironmentCheck($stmt->cond) ? $state->localOnly() : $state;
                $this->collectStatements($stmt->stmts, $file, $guarded);
                foreach ($stmt->elseifs as $elseif) {
                    $this->collectStatements($elseif->stmts, $file, $state);
                }
                if ($stmt->else) {
                    $this->collectStatements($stmt->else->stmts, $file, $state);
                }
            } elseif ($stmt instanceof Node\Stmt\Return_ && $stmt->expr) {
                $this->collectExpression($stmt->expr, $file, $state);
            }
        }
    }

    private function collectExpression(Node\Expr $expr, string $file, GroupState $state): void
    {
        if ($expr instanceof Node\Expr\Include_) {
            if ($target = $this->resolveFile($expr->expr, $file)) {
                $this->collectFile($target, $state);
            }

            return;
        }

        $chain = $this->unwind($expr);
        if ($chain === null) {
            return;
        }

        $current = $state;
        foreach ($chain as $index => $call) {
            $name = $call['name'];

            if ($name === 'group') {
                $args = $call['args'];
                // Route::group(['prefix' => ..., 'middleware' => ...], $routes)
                if (count($args) > 1 && $args[0] instanceof Node\Expr\Array_) {
                    $current = $this->applyArrayAttributes($current, $args[0]);
                }
                $this->collectGroupBody(end($args) ?: null, $file, $current);

                return;
            }

            if (in_array($name, self::VERBS, true)) {
                $this->addRoute($name, $call['args'], array_slice($chain, $index + 1), $file, $call['line'], $current);

                return;
            }

            if (in_array($name, self::RESOURCE, true)) {
                $this->addResource($call['args'], array_slice($chain, $index + 1), $file, $call['line'], $current, $name === 'apiResource');

                return;
            }

            if (! in_array($name, self::ATTRIBUTES, true)) {
                return;
            }

            $current = $this->applyAttribute($current, $name, $call['args']);
        }
    }

    private function collectGroupBody(?Node\Expr $body, string $file, GroupState $state): void
    {
        if ($body instanceof Node\Expr\Closure) {
            $this->collectStatements($body->stmts, $file, $state);
        } elseif ($body instanceof Node\Expr\ArrowFunction) {
            $this->collectExpression($body->expr, $file, $state);
        } elseif ($body !== null && ($target = $this->resolveFile($body, $file))) {
            $this->collectFile($target, $state);
        }
    }

    /**
     * @param  Node\Expr[]  $args
     * @param  array<int, array{name: string, args: Node\Expr[], line: int}>  $after
     */
    private function addRoute(string $verb, array $args, array $after, string $file, int $line, GroupState $state): void
    {
        $offset = 0;
        $methods = match ($verb) {
            'any' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
            'view', 'redirect', 'permanentRedirect' => ['GET'],
            'match' => $this->strings($args[$offset++] ?? null, upper: true),
            default => [strtoupper($verb)],
        };

        $uri = $this->string($args[$offset] ?? null);
        if ($uri === null) {
            return;
        }

        [$controller, $action, $closure, $middleware] = $this->action($args[$offset + 1] ?? null, $state);
        $state = $state->withMiddleware($middleware);

        foreach ($after as $call) {
            $state = in_array($call['name'], ['middleware', 'withoutMiddleware'], true)
                ? $this->applyAttribute($state, $call['name'], $call['args'])
                : $state;
        }

        $this->routes[] = new Route(
            methods: $methods,
            uri: $state->uri($uri),
            middleware: $state->middleware,
            controller: $controller,
            action: $action,
            closure: $closure,
            file: $file,
            line: $line,
            localOnly: $state->localOnly,
        );
    }

    /** Route::resource('photos', PhotoController::class) registers the CRUD routes. */
    private function addResource(array $args, array $after, string $file, int $line, GroupState $state, bool $api): void
    {
        $uri = $this->string($args[0] ?? null);
        $controller = $this->className($args[1] ?? null) ?? $state->controller;
        if ($uri === null) {
            return;
        }

        foreach ($after as $call) {
            $state = in_array($call['name'], ['middleware', 'withoutMiddleware'], true)
                ? $this->applyAttribute($state, $call['name'], $call['args'])
                : $state;
        }

        $member = $uri.'/{id}';
        $routes = [
            ['GET', $uri, 'index'], ['POST', $uri, 'store'], ['GET', $member, 'show'],
            ['PUT', $member, 'update'], ['PATCH', $member, 'update'], ['DELETE', $member, 'destroy'],
        ];
        if (! $api) {
            $routes[] = ['GET', $uri.'/create', 'create'];
            $routes[] = ['GET', $member.'/edit', 'edit'];
        }

        foreach ($routes as [$method, $path, $action]) {
            $this->routes[] = new Route([$method], $state->uri($path), $state->middleware, $controller, $action, null, $file, $line, $state->localOnly);
        }
    }

    /**
     * The route action: [Controller::class, 'method'], Controller::class,
     * 'Controller@method', ['uses' => ..., 'middleware' => ...] or a closure.
     *
     * @return array{0: ?string, 1: ?string, 2: ?Node, 3: string[]}
     */
    private function action(?Node\Expr $expr, GroupState $state): array
    {
        if ($expr instanceof Node\Expr\Closure || $expr instanceof Node\Expr\ArrowFunction) {
            return [null, null, $expr, []];
        }

        if ($class = $this->className($expr)) {
            return [$class, '__invoke', null, []];
        }

        if ($expr instanceof Node\Expr\Array_) {
            $items = array_values(array_filter($expr->items));
            // [Controller::class, 'method']
            if (count($items) === 2 && $items[0]->key === null && ($class = $this->className($items[0]->value))) {
                return [$class, $this->string($items[1]->value), null, []];
            }

            $uses = null;
            $middleware = [];
            $closure = null;
            foreach ($items as $item) {
                $key = $this->string($item->key);
                if ($key === 'uses') {
                    $uses = $item->value;
                } elseif ($key === 'middleware') {
                    $middleware = $this->strings($item->value);
                } elseif ($key === null && ($item->value instanceof Node\Expr\Closure || $item->value instanceof Node\Expr\ArrowFunction)) {
                    $closure = $item->value;
                }
            }
            if ($closure) {
                return [null, null, $closure, $middleware];
            }
            [$controller, $action] = $this->parseUses($this->string($uses), $state);

            return [$controller, $action, null, $middleware];
        }

        // 'Controller@method', or a bare method name inside Route::controller()
        [$controller, $action] = $this->parseUses($this->string($expr), $state);

        return [$controller, $action, null, []];
    }

    /** @return array{0: ?string, 1: ?string} */
    private function parseUses(?string $uses, GroupState $state): array
    {
        if ($uses === null) {
            return [null, null];
        }
        if (! str_contains($uses, '@')) {
            return [$state->controller, $uses];
        }

        [$class, $method] = explode('@', $uses, 2);
        if (! str_starts_with($class, '\\')) {
            $class = rtrim($state->namespace ?? 'App\\Http\\Controllers', '\\').'\\'.$class;
        }

        return [ltrim($class, '\\'), $method];
    }

    private function applyAttribute(GroupState $state, string $name, array $args): GroupState
    {
        return match ($name) {
            'middleware' => $state->withMiddleware($this->strings($args[0] ?? null)),
            'withoutMiddleware' => $state->withoutMiddleware($this->strings($args[0] ?? null)),
            'can' => $state->withMiddleware(['can:'.($this->string($args[0] ?? null) ?? '')]),
            'prefix' => $state->withPrefix($this->string($args[0] ?? null) ?? ''),
            'controller' => $state->withController($this->className($args[0] ?? null) ?? $this->string($args[0] ?? null)),
            'namespace' => $state->withNamespace($this->string($args[0] ?? null)),
            default => $state,
        };
    }

    private function applyArrayAttributes(GroupState $state, Node\Expr\Array_ $array): GroupState
    {
        foreach (array_filter($array->items) as $item) {
            $key = $this->string($item->key);
            if (in_array($key, ['middleware', 'prefix', 'namespace', 'controller'], true)) {
                $state = $this->applyAttribute($state, $key, [$item->value]);
            }
        }

        return $state;
    }

    /**
     * Route::middleware('auth')->prefix('admin')->group(...) as a root-first
     * list of calls, or null when the expression is not a Route facade chain.
     *
     * @return array<int, array{name: string, args: Node\Expr[], line: int}>|null
     */
    private function unwind(Node\Expr $expr): ?array
    {
        $calls = [];
        while ($expr instanceof Node\Expr\MethodCall) {
            if (! $expr->name instanceof Node\Identifier) {
                return null;
            }
            array_unshift($calls, ['name' => $expr->name->toString(), 'args' => $this->args($expr), 'line' => $expr->getStartLine()]);
            $expr = $expr->var;
        }

        if (! $expr instanceof Node\Expr\StaticCall || ! $expr->class instanceof Node\Name || ! $expr->name instanceof Node\Identifier) {
            return null;
        }
        $class = $expr->class->toString();
        if ($class !== 'Route' && ! str_ends_with($class, '\\Route')) {
            return null;
        }

        array_unshift($calls, ['name' => $expr->name->toString(), 'args' => $this->args($expr), 'line' => $expr->getStartLine()]);

        return $calls;
    }

    /** @return Node\Expr[] */
    private function args(Node\Expr\CallLike $call): array
    {
        return array_values(array_map(
            fn (Node\Arg $arg) => $arg->value,
            array_filter($call->getRawArgs(), fn ($arg) => $arg instanceof Node\Arg),
        ));
    }

    /**
     * Registration that depends on the environment (app()->environment('local'),
     * isLocal(), config('app.debug')) or on a marker file, like an installer
     * whose routes exist only while an INSTALLING file does.
     */
    private function isEnvironmentCheck(Node\Expr $cond): bool
    {
        $finder = new NodeFinder;
        if ($finder->findFirst($cond, fn (Node $node) => $node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name
            && in_array(strtolower($node->name->toString()), ['file_exists', 'is_file'], true))) {
            return true;
        }

        $calls = $finder->find($cond, fn (Node $node) => ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\FuncCall || $node instanceof Node\Expr\StaticCall)
            && ($node->name instanceof Node\Identifier || $node->name instanceof Node\Name)
            && in_array(strtolower($node->name->toString()), ['environment', 'islocal', 'runningunittests', 'isproduction', 'env', 'config'], true));
        $strings = $finder->find($cond, fn (Node $node) => $node instanceof Node\Scalar\String_
            && in_array(strtolower($node->value), ['local', 'testing', 'development', 'dev', 'app.debug', 'app_debug', 'app_env', 'app.env'], true));

        return $calls !== [] && $strings !== [] || array_filter($calls, fn ($call) => in_array(strtolower($call->name->toString()), ['islocal', 'runningunittests'], true)) !== [];
    }

    /** __DIR__.'/auth.php', base_path('routes/admin.php') or a literal path. */
    private function resolveFile(Node\Expr $expr, string $from): ?string
    {
        if ($expr instanceof Node\Expr\BinaryOp\Concat && $expr->left instanceof Node\Scalar\MagicConst\Dir) {
            $relative = $this->string($expr->right);

            return $relative === null ? null : $this->normalise(dirname($from).'/'.ltrim($relative, '/'));
        }
        if ($expr instanceof Node\Expr\FuncCall && $expr->name instanceof Node\Name && $expr->name->toString() === 'base_path') {
            $relative = $this->string($this->args($expr)[0] ?? null);

            return $relative === null ? null : $this->normalise($relative);
        }
        $literal = $this->string($expr);

        return $literal === null ? null : $this->normalise(str_starts_with($literal, '/') ? $this->ctx->relativize($literal) : $literal);
    }

    private function normalise(string $path): string
    {
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '..') {
                array_pop($parts);
            } elseif ($part !== '.' && $part !== '') {
                $parts[] = $part;
            }
        }

        return implode('/', $parts);
    }

    private function className(?Node $expr): ?string
    {
        return $expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name
            && $expr->name instanceof Node\Identifier && strtolower($expr->name->toString()) === 'class'
            ? $expr->class->toString()
            : null;
    }

    private function string(?Node $expr): ?string
    {
        return match (true) {
            $expr instanceof Node\Scalar\String_ => $expr->value,
            $expr instanceof Node\Identifier => $expr->toString(),
            default => null,
        };
    }

    /** @return string[] */
    private function strings(?Node $expr, bool $upper = false): array
    {
        $values = match (true) {
            $expr instanceof Node\Expr\Array_ => array_map(fn ($item) => $this->string($item->value) ?? $this->className($item->value), array_filter($expr->items)),
            default => [$this->string($expr) ?? $this->className($expr)],
        };
        $values = array_values(array_filter($values, fn ($value) => $value !== null && $value !== ''));

        return $upper ? array_map('strtoupper', $values) : $values;
    }
}
