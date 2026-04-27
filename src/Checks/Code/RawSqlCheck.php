<?php

namespace Stackshield\Scanner\Checks\Code;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class RawSqlCheck implements Check
{
    private const DANGEROUS_METHODS = [
        'raw', 'selectRaw', 'whereRaw', 'orWhereRaw',
        'havingRaw', 'orHavingRaw', 'orderByRaw', 'groupByRaw',
    ];

    private const TAINT_SOURCES = [
        'request', 'input', 'get', 'post', 'query', 'all',
    ];

    public function id(): string
    {
        return 'SS002';
    }

    public function name(): string
    {
        return 'Raw SQL with Tainted Input';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
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
            $staticCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\StaticCall::class);

            foreach (array_merge($methodCalls, $staticCalls) as $call) {
                $methodName = $call->name instanceof Node\Identifier ? $call->name->toString() : null;
                if ($methodName === null || ! in_array($methodName, self::DANGEROUS_METHODS, true)) {
                    continue;
                }

                // Check if any argument contains tainted input
                foreach ($call->args as $arg) {
                    if ($this->containsTaintedInput($arg->value)) {
                        $className = $this->resolveClassName($call, $stmts, $nodeFinder);
                        $prettyPrinter = new \PhpParser\PrettyPrinter\Standard;
                        $snippet = $prettyPrinter->prettyPrintExpr($call);

                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $this->severity(),
                            category: $this->category(),
                            message: "Call to {$methodName}() with potentially tainted input. User-controlled data may reach this SQL query without parameter binding.",
                            file: $file,
                            line: $call->getStartLine(),
                            symbol: $className,
                            snippet: strlen($snippet) > 200 ? substr($snippet, 0, 200).'...' : $snippet,
                            remediation: 'Use parameter bindings instead of string interpolation: ->whereRaw("column = ?", [$value])',
                        );

                        break; // One finding per call
                    }
                }
            }
        }
    }

    private function containsTaintedInput(Node\Expr $expr): bool
    {
        // Direct request() call
        if ($expr instanceof Node\Expr\FuncCall) {
            $name = $expr->name instanceof Node\Name ? $expr->name->toString() : null;
            if ($name === 'request') {
                return true;
            }
        }

        // $request->input(), $request->get(), etc.
        if ($expr instanceof Node\Expr\MethodCall) {
            if ($expr->var instanceof Node\Expr\Variable && $expr->var->name === 'request') {
                return true;
            }
            // Chain: request()->input()
            if ($expr->var instanceof Node\Expr\FuncCall) {
                $name = $expr->var->name instanceof Node\Name ? $expr->var->name->toString() : null;
                if ($name === 'request') {
                    return true;
                }
            }
        }

        // Variable named $request or common input vars
        if ($expr instanceof Node\Expr\Variable) {
            $name = is_string($expr->name) ? $expr->name : null;
            if (in_array($name, ['request', '_GET', '_POST', '_REQUEST'], true)) {
                return true;
            }
        }

        // String concatenation or interpolation containing tainted input
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->containsTaintedInput($expr->left) || $this->containsTaintedInput($expr->right);
        }

        // Encapsed string (double-quoted with variables)
        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->containsTaintedInput($part)) {
                    return true;
                }
            }
        }

        // Array access on tainted variable
        if ($expr instanceof Node\Expr\ArrayDimFetch) {
            if ($expr->var instanceof Node\Expr && $this->containsTaintedInput($expr->var)) {
                return true;
            }
        }

        return false;
    }

    private function resolveClassName(Node\Expr $call, array $stmts, NodeFinder $nodeFinder): ?string
    {
        $classes = $nodeFinder->findInstanceOf($stmts, Node\Stmt\Class_::class);
        foreach ($classes as $class) {
            if ($call->getStartLine() >= $class->getStartLine() && $call->getEndLine() <= $class->getEndLine()) {
                return $class->namespacedName?->toString() ?? $class->name?->toString();
            }
        }

        return null;
    }
}
