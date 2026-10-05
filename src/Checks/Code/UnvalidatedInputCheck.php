<?php

namespace StackShield\Analyser\Checks\Code;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Advisory;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class UnvalidatedInputCheck implements Advisory, Check
{
    public function id(): string
    {
        return 'SS007';
    }

    public function name(): string
    {
        return 'Controller Without Validation';
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
                foreach ($class->stmts as $stmt) {
                    if (! ($stmt instanceof Node\Stmt\ClassMethod)) {
                        continue;
                    }

                    if ($stmt->isPrivate() || $stmt->isProtected()) {
                        continue;
                    }

                    // Check if method accepts Request parameter
                    $hasRequestParam = false;
                    foreach ($stmt->params as $param) {
                        $type = $param->type;
                        if ($type instanceof Node\Name) {
                            $typeName = $type->toString();
                            if (str_contains($typeName, 'Request') && ! str_contains($typeName, 'FormRequest')) {
                                $hasRequestParam = true;
                                break;
                            }
                        }
                    }

                    if (! $hasRequestParam) {
                        continue;
                    }

                    // Check if the method calls validate() or uses FormRequest
                    $hasValidation = $this->hasValidation($stmt, $nodeFinder);

                    if (! $hasValidation) {
                        $methodName = $stmt->name->toString();
                        $className = $class->namespacedName?->toString() ?? $class->name?->toString() ?? 'Unknown';

                        // Only flag store/update/create type methods (state-changing)
                        $stateChanging = in_array($methodName, ['store', 'update', 'create', 'save', 'destroy', 'delete', 'post', 'put', 'patch'], true);
                        if (! $stateChanging) {
                            continue;
                        }

                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $this->severity(),
                            category: $this->category(),
                            message: "Method {$className}::{$methodName}() accepts Request but doesn't call validate(). Input may be used without validation.",
                            file: $file,
                            line: $stmt->getStartLine(),
                            symbol: "{$className}::{$methodName}",
                            remediation: 'Add \$request->validate([...]) or use a FormRequest class to validate input.',
                        );
                    }
                }
            }
        }
    }

    private function hasValidation(Node\Stmt\ClassMethod $method, NodeFinder $nodeFinder): bool
    {
        $methodCalls = $nodeFinder->findInstanceOf([$method], Node\Expr\MethodCall::class);

        foreach ($methodCalls as $call) {
            if ($call->name instanceof Node\Identifier) {
                $name = $call->name->toString();
                if (in_array($name, ['validate', 'validated', 'safe'], true)) {
                    return true;
                }
            }
        }

        return false;
    }
}
