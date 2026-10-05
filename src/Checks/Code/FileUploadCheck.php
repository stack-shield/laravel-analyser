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

class FileUploadCheck implements Advisory, Check
{
    public function id(): string
    {
        return 'SS009';
    }

    public function name(): string
    {
        return 'Unrestricted File Upload';
    }

    public function severity(): Severity
    {
        return Severity::High;
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

        foreach ($ctx->phpFiles('app') as $file) {
            $stmts = $ctx->ast($file);
            if (empty($stmts)) {
                continue;
            }

            $methodCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\MethodCall::class);

            foreach ($methodCalls as $call) {
                if (! ($call->name instanceof Node\Identifier)) {
                    continue;
                }

                $methodName = $call->name->toString();

                // Look for file store/move without validation
                if (! in_array($methodName, ['store', 'storeAs', 'move', 'storePublicly', 'storePubliclyAs'], true)) {
                    continue;
                }

                // Check if the call is on a file/uploaded file object
                if (! $this->isOnFileObject($call)) {
                    continue;
                }

                // Check if there's validation for file type nearby
                if (! $this->hasFileValidation($call, $stmts, $nodeFinder)) {
                    $className = $this->resolveClassName($call, $stmts, $nodeFinder);

                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: "File upload via {$methodName}() without apparent file type validation. Attackers could upload executable files.",
                        file: $file,
                        line: $call->getStartLine(),
                        symbol: $className,
                        remediation: "Validate file type before storing: \$request->validate(['file' => 'file|mimes:jpg,png,pdf|max:10240'])",
                    );
                }
            }
        }
    }

    private function isOnFileObject(Node\Expr\MethodCall $call): bool
    {
        // Check if called on $request->file(...) or variable that looks like a file
        if ($call->var instanceof Node\Expr\MethodCall) {
            $innerMethod = $call->var->name instanceof Node\Identifier ? $call->var->name->toString() : '';
            if ($innerMethod === 'file') {
                return true;
            }
        }

        if ($call->var instanceof Node\Expr\Variable) {
            $varName = is_string($call->var->name) ? $call->var->name : '';
            if (str_contains(strtolower($varName), 'file') || str_contains(strtolower($varName), 'upload') || str_contains(strtolower($varName), 'image')) {
                return true;
            }
        }

        return false;
    }

    private function hasFileValidation(Node\Expr $call, array $stmts, NodeFinder $nodeFinder): bool
    {
        $allMethodCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\MethodCall::class);

        foreach ($allMethodCalls as $mc) {
            if (! ($mc->name instanceof Node\Identifier)) {
                continue;
            }
            $name = $mc->name->toString();
            if ($name === 'validate' && abs($mc->getStartLine() - $call->getStartLine()) < 20) {
                return true;
            }
        }

        return false;
    }

    private function resolveClassName(Node\Expr $node, array $stmts, NodeFinder $nodeFinder): ?string
    {
        $classes = $nodeFinder->findInstanceOf($stmts, Node\Stmt\Class_::class);
        foreach ($classes as $class) {
            if ($node->getStartLine() >= $class->getStartLine() && $node->getEndLine() <= $class->getEndLine()) {
                return $class->namespacedName?->toString() ?? $class->name?->toString();
            }
        }

        return null;
    }
}
