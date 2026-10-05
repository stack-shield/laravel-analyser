<?php

namespace StackShield\Analyser\Routes;

/** The attributes accumulated by the route groups enclosing a declaration. */
final class GroupState
{
    /** @param string[] $middleware */
    public function __construct(
        public readonly string $prefix = '',
        public readonly array $middleware = [],
        public readonly ?string $controller = null,
        public readonly ?string $namespace = null,
        public readonly bool $localOnly = false,
    ) {}

    public function uri(string $uri): string
    {
        return trim(trim($this->prefix, '/').'/'.trim($uri, '/'), '/');
    }

    /** @param string[] $middleware */
    public function withMiddleware(array $middleware): self
    {
        return new self($this->prefix, array_values(array_unique([...$this->middleware, ...$middleware])), $this->controller, $this->namespace, $this->localOnly);
    }

    /** @param string[] $middleware */
    public function withoutMiddleware(array $middleware): self
    {
        return new self($this->prefix, array_values(array_diff($this->middleware, $middleware)), $this->controller, $this->namespace, $this->localOnly);
    }

    public function withPrefix(string $prefix): self
    {
        return new self($this->uri($prefix), $this->middleware, $this->controller, $this->namespace, $this->localOnly);
    }

    public function withController(?string $controller): self
    {
        return new self($this->prefix, $this->middleware, $controller, $this->namespace, $this->localOnly);
    }

    public function withNamespace(?string $namespace): self
    {
        if ($namespace === null) {
            return $this;
        }
        // Nested group namespaces append, as Laravel's did before 8.
        $full = $this->namespace !== null && ! str_starts_with($namespace, '\\')
            ? rtrim($this->namespace, '\\').'\\'.$namespace
            : ltrim($namespace, '\\');

        return new self($this->prefix, $this->middleware, $this->controller, $full, $this->localOnly);
    }

    public function localOnly(): self
    {
        return new self($this->prefix, $this->middleware, $this->controller, $this->namespace, true);
    }
}
