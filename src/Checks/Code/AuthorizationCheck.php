<?php

namespace StackShield\Analyser\Checks\Code;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class AuthorizationCheck implements Check
{
    private const RESOURCE_METHODS = ['store', 'update', 'destroy', 'delete', 'edit'];

    private const AUTH_PATTERNS = [
        'authorize',
        'can',
        'cannot',
        'allows',
        'denies',
        'Gate::allows',
        'Gate::denies',
        'Gate::check',
        'Gate::authorize',
        'policy',
        'authorizeResource',
        'authorizeForUser',
    ];

    public function id(): string
    {
        return 'SS053';
    }

    public function name(): string
    {
        return 'Missing Authorization in Controllers';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function category(): Category
    {
        return Category::Code;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $nodeFinder = new NodeFinder;

        foreach ($ctx->phpFiles('app/Http/Controllers') as $file) {
            $stmts = $ctx->ast($file);
            if (empty($stmts)) {
                continue;
            }

            $classes = $nodeFinder->findInstanceOf($stmts, Node\Stmt\Class_::class);

            foreach ($classes as $class) {
                // Check if class-level authorization is applied (e.g., authorizeResource in constructor)
                $classContents = $ctx->fileContents($file);
                if ($classContents === null) {
                    continue;
                }

                $hasConstructorAuth = false;
                if (preg_match('/function\s+__construct\s*\([^)]*\)\s*\{[^}]*authorizeResource/s', $classContents)) {
                    $hasConstructorAuth = true;
                }

                if ($hasConstructorAuth) {
                    continue;
                }

                foreach ($class->stmts as $stmt) {
                    if (! ($stmt instanceof Node\Stmt\ClassMethod)) {
                        continue;
                    }

                    $methodName = $stmt->name->toString();
                    if (! in_array($methodName, self::RESOURCE_METHODS, true)) {
                        continue;
                    }

                    // Get the method body as text to check for auth calls
                    $methodStart = $stmt->getStartLine();
                    $methodEnd = $stmt->getEndLine();
                    $lines = explode("\n", $classContents);
                    $methodBody = implode("\n", array_slice($lines, $methodStart - 1, $methodEnd - $methodStart + 1));

                    $hasAuth = false;
                    foreach (self::AUTH_PATTERNS as $pattern) {
                        if (str_contains($methodBody, $pattern)) {
                            $hasAuth = true;
                            break;
                        }
                    }

                    if (! $hasAuth) {
                        $className = $class->namespacedName?->toString() ?? $class->name?->toString() ?? 'Unknown';

                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $this->severity(),
                            category: $this->category(),
                            message: "Controller method {$className}::{$methodName}() performs a resource operation without authorization checks. Any authenticated user may be able to modify resources they do not own.",
                            file: $file,
                            line: $stmt->getStartLine(),
                            symbol: $className.'::'.$methodName,
                            snippet: "public function {$methodName}(...)",
                            remediation: 'Add authorization using $this->authorize(\''.($methodName === 'destroy' ? 'delete' : $methodName).'\', $model), Gate::authorize(), or a Form Request with authorize() returning a policy check.',
                        );
                    }
                }
            }
        }
    }
}
