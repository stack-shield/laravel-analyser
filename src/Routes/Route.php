<?php

namespace StackShield\Analyser\Routes;

use PhpParser\Node;

/**
 * A route as Laravel would register it: the full URI after group prefixes and
 * every middleware applied by its groups, its own chain and its controller.
 */
final class Route
{
    /** Middleware that only lets authenticated or authorised users through. */
    /** Middleware classes that authenticate: Authenticate, DaemonAuthenticate, AuthenticateSession... */
    private const AUTH_CLASS = '/(?:^|\\\\)(?!RedirectIf|Guest)\w*(?:Authenticat\w*|RequireAdmin\w*|AdminMiddleware|IsAdmin|EnsureUserIsAdmin|VerifyAdmins?)$/i';

    private const AUTH_MIDDLEWARE = '/^(?:auth(?:[:.].*)?|can:.*|role(?::.*)?|permission(?::.*)?|admin|is_admin|verified|password\.confirm|signed|abilities:.*|ability:.*)$/i';

    /**
     * @param  string[]  $methods  Upper-case HTTP verbs.
     * @param  string[]  $middleware
     */
    public function __construct(
        public readonly array $methods,
        public readonly string $uri,
        public readonly array $middleware,
        public readonly ?string $controller,
        public readonly ?string $action,
        public readonly ?Node $closure,
        public readonly string $file,
        public readonly int $line,
        /** Registered only under an environment or marker-file condition. */
        public readonly bool $localOnly,
        public readonly array $expandedMiddleware = [],
    ) {}

    /** @param string[] $expanded Middleware with groups and aliases resolved to classes. */
    public function withExpandedMiddleware(array $expanded): self
    {
        return new self($this->methods, $this->uri, $this->middleware, $this->controller, $this->action, $this->closure, $this->file, $this->line, $this->localOnly, $expanded);
    }

    public function isStateChanging(): bool
    {
        return array_intersect($this->methods, ['POST', 'PUT', 'PATCH', 'DELETE']) !== [];
    }

    public function inGroup(string $group): bool
    {
        return in_array($group, $this->middleware, true);
    }

    /** Behind authentication or authorisation, by route middleware alone. */
    public function hasAuthMiddleware(): bool
    {
        foreach ([...$this->middleware, ...$this->expandedMiddleware] as $middleware) {
            if (preg_match(self::AUTH_MIDDLEWARE, $middleware) || preg_match(self::AUTH_CLASS, $middleware)) {
                return true;
            }
        }

        return false;
    }

    /** Behind authentication in a session (cookie) guard, which is what CSRF protects. */
    public function hasSessionAuth(): bool
    {
        foreach ([...$this->middleware, ...$this->expandedMiddleware] as $middleware) {
            if (preg_match('/^(?:auth|auth:web|auth\.session|verified|password\.confirm)$/i', $middleware)
                || preg_match('/(?:^|\\\\)(?:Authenticate|AuthenticateSession)$/', $middleware)) {
                return true;
            }
        }

        return false;
    }

    /** Laravel's Str::is matching of a CSRF exception pattern against this URI. */
    public function matches(string $pattern): bool
    {
        $pattern = trim($pattern, '/');
        if ($pattern === '*') {
            return true;
        }
        $regex = '#^'.str_replace('\*', '.*', preg_quote($pattern, '#')).'\z#u';

        return (bool) preg_match($regex, $this->uri);
    }
}
