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

class DebugRoutesCheck implements Check
{
    public function id(): string
    {
        return 'SS051';
    }

    public function name(): string
    {
        return 'Debug/Test Routes in Production';
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
        return 3;
    }

    /**
     * A debug endpoint is only exposed when anyone can reach it: not behind
     * auth (route, group or controller middleware) and not registered only
     * inside an environment check.
     */
    public function run(Context $ctx): iterable
    {
        foreach (RouteCollector::routes($ctx) as $route) {
            if ($route->localOnly) {
                continue;
            }

            $description = $this->debugRoute($route);
            if ($description === null || RouteCollector::requiresAuth($ctx, $route)) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: "Debug route '/{$route->uri}' is reachable without authentication. {$description}.",
                file: $route->file,
                line: $route->line,
                symbol: $route->uri,
                remediation: 'Remove debug and test routes before deploying to production, put them behind auth, or register them only inside an environment check: if (app()->environment(\'local\')) { ... }',
            );
        }
    }

    /**
     * Whole-route debug endpoints. Features named "test" (send a test email,
     * test a webhook, rules/{rule}/test) are not debug routes, so the URI has
     * to be a debug endpoint itself, or the closure has to dump data.
     */
    private function debugRoute(Route $route): ?string
    {
        if ($route->closure !== null && (new NodeFinder)->findFirst($route->closure, fn (Node $node) => $node instanceof Node\Expr\FuncCall
            && $node->name instanceof Node\Name && in_array(strtolower($node->name->toString()), ['phpinfo', 'dd', 'dump', 'var_dump'], true))) {
            return 'Its closure calls phpinfo() or dumps data, exposing configuration and environment variables';
        }

        $segments = explode('/', strtolower($route->uri));
        if (in_array('phpinfo', $segments, true) || strtolower((string) $route->action) === 'phpinfo') {
            return 'A phpinfo page exposes the full PHP configuration and environment variables';
        }
        if (in_array($segments[0], ['debug', '_debug', 'test', 'tests', 'dump'], true)) {
            return 'It looks like a leftover debug or test endpoint that may expose application internals';
        }

        return null;
    }
}
