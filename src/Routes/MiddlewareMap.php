<?php

namespace StackShield\Analyser\Routes;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Context;

/**
 * The app's middleware aliases and groups, from app/Http/Kernel.php (Laravel
 * 10 and earlier) and bootstrap/app.php (11+), so a route's middleware can be
 * resolved to the classes that actually run.
 */
final class MiddlewareMap
{
    /**
     * @param  array<string, string>  $aliases
     * @param  array<string, string[]>  $groups
     */
    private function __construct(
        private readonly array $aliases,
        private readonly array $groups,
    ) {}

    public static function for(Context $ctx): self
    {
        $aliases = [];
        $groups = [];
        $finder = new NodeFinder;

        foreach ($finder->findInstanceOf($ctx->ast('app/Http/Kernel.php'), Node\PropertyItem::class) as $property) {
            $name = $property->name->toString();
            if (! $property->default instanceof Node\Expr\Array_) {
                continue;
            }
            if (in_array($name, ['routeMiddleware', 'middlewareAliases'], true)) {
                $aliases += self::map($property->default);
            } elseif ($name === 'middlewareGroups') {
                foreach (array_filter($property->default->items) as $item) {
                    if (($group = self::value($item->key)) !== null) {
                        $groups[$group] = self::list($item->value);
                    }
                }
            }
        }

        foreach ($finder->findInstanceOf($ctx->ast('bootstrap/app.php'), Node\Expr\MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier) {
                continue;
            }
            $args = array_values(array_filter($call->getRawArgs(), fn ($arg) => $arg instanceof Node\Arg));
            $method = $call->name->toString();

            if ($method === 'alias' && isset($args[0]) && $args[0]->value instanceof Node\Expr\Array_) {
                $aliases += self::map($args[0]->value);
            } elseif (in_array($method, ['group', 'appendToGroup', 'prependToGroup'], true) && isset($args[1])) {
                $group = self::value($args[0]->value);
                if ($group !== null) {
                    $groups[$group] = [...($groups[$group] ?? []), ...self::list($args[1]->value)];
                }
            } elseif (in_array($method, ['web', 'api'], true)) {
                foreach ($args as $arg) {
                    $groups[$method] = [...($groups[$method] ?? []), ...self::list($arg->value)];
                }
            }
        }

        return new self($aliases, $groups);
    }

    /**
     * The given middleware plus every group member and alias target they
     * resolve to.
     *
     * @param  string[]  $middleware
     * @return string[]
     */
    public function expand(array $middleware): array
    {
        $seen = [];
        $queue = $middleware;

        while ($queue !== []) {
            $name = array_shift($queue);
            if (isset($seen[$name])) {
                continue;
            }
            $seen[$name] = true;

            $base = explode(':', $name, 2)[0];
            foreach ($this->groups[$name] ?? $this->groups[$base] ?? [] as $member) {
                $queue[] = $member;
            }
            if (isset($this->aliases[$base])) {
                $queue[] = $this->aliases[$base];
            }
        }

        return array_keys($seen);
    }

    /** @return array<string, string> */
    private static function map(Node\Expr\Array_ $array): array
    {
        $map = [];
        foreach (array_filter($array->items) as $item) {
            $key = self::value($item->key);
            $value = self::value($item->value);
            if ($key !== null && $value !== null) {
                $map[$key] = $value;
            }
        }

        return $map;
    }

    /** @return string[] */
    private static function list(Node\Expr $expr): array
    {
        $values = $expr instanceof Node\Expr\Array_
            ? array_map(fn ($item) => self::value($item->value), array_filter($expr->items))
            : [self::value($expr)];

        return array_values(array_filter($values, fn ($value) => $value !== null));
    }

    private static function value(?Node $expr): ?string
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $expr->value;
        }
        if ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name) {
            return $expr->class->toString();
        }

        return null;
    }
}
