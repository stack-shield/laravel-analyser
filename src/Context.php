<?php

namespace Stackshield\Scanner;

use Illuminate\Support\Collection;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class Context
{
    public readonly string $basePath;

    private Parser $parser;

    /** @var array<string, Node\Stmt[]> */
    private array $astCache = [];

    private ?array $envCache = null;

    private ?array $composerLockCache = null;

    private ?array $composerJsonCache = null;

    public function __construct(
        string $basePath,
        private readonly array $config = [],
    ) {
        $resolved = realpath($basePath);
        $this->basePath = $resolved !== false ? $resolved : $basePath;
        $this->parser = (new ParserFactory)->createForNewestSupportedVersion();
    }

    /** @return Node\Stmt[] */
    public function ast(string $file): array
    {
        $absolutePath = $this->resolve($file);

        if (isset($this->astCache[$absolutePath])) {
            return $this->astCache[$absolutePath];
        }

        if (! file_exists($absolutePath)) {
            return $this->astCache[$absolutePath] = [];
        }

        $code = file_get_contents($absolutePath);
        $stmts = $this->parser->parse($code) ?? [];

        $traverser = new NodeTraverser;
        $traverser->addVisitor(new NameResolver);
        $stmts = $traverser->traverse($stmts);

        return $this->astCache[$absolutePath] = $stmts;
    }

    /** @return iterable<string> Relative paths */
    public function phpFiles(string $path = 'app'): iterable
    {
        $absolutePath = $this->resolve($path);
        if (! is_dir($absolutePath)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($absolutePath, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        /** @var SplFileInfo $file */
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                yield $this->relativize($file->getRealPath());
            }
        }
    }

    public function env(?string $filename = '.env'): array
    {
        $cacheKey = $filename ?? '.env';
        if ($cacheKey === '.env' && $this->envCache !== null) {
            return $this->envCache;
        }

        $path = $this->resolve($filename);
        if (! file_exists($path)) {
            return [];
        }

        $parsed = $this->parseEnvFile($path);

        if ($cacheKey === '.env') {
            $this->envCache = $parsed;
        }

        return $parsed;
    }

    public function envFiles(): array
    {
        $files = [];
        $candidates = ['.env', '.env.production', '.env.staging', '.env.example'];

        foreach ($candidates as $candidate) {
            if (file_exists($this->resolve($candidate))) {
                $files[] = $candidate;
            }
        }

        return $files;
    }

    public function composerLock(): array
    {
        if ($this->composerLockCache !== null) {
            return $this->composerLockCache;
        }

        $path = $this->resolve('composer.lock');
        if (! file_exists($path)) {
            return $this->composerLockCache = [];
        }

        return $this->composerLockCache = json_decode(file_get_contents($path), true) ?? [];
    }

    public function composerJson(): array
    {
        if ($this->composerJsonCache !== null) {
            return $this->composerJsonCache;
        }

        $path = $this->resolve('composer.json');
        if (! file_exists($path)) {
            return $this->composerJsonCache = [];
        }

        return $this->composerJsonCache = json_decode(file_get_contents($path), true) ?? [];
    }

    public function fileExists(string $relativePath): bool
    {
        return file_exists($this->resolve($relativePath));
    }

    public function fileContents(string $relativePath): ?string
    {
        $path = $this->resolve($relativePath);

        return file_exists($path) ? file_get_contents($path) : null;
    }

    public function config(): array
    {
        return $this->config;
    }

    public function resolve(string $relativePath): string
    {
        return $this->basePath.'/'.ltrim($relativePath, '/');
    }

    public function relativize(string $absolutePath): string
    {
        $prefix = rtrim($this->basePath, '/').'/';
        if (str_starts_with($absolutePath, $prefix)) {
            return substr($absolutePath, strlen($prefix));
        }

        return $absolutePath;
    }

    private function parseEnvFile(string $path): array
    {
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $env = [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (str_contains($line, '=')) {
                [$key, $value] = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                // Remove surrounding quotes
                $value = trim($value, '"\'');
                $env[$key] = $value;
            }
        }

        return $env;
    }
}
