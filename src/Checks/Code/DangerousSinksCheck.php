<?php

namespace StackShield\Analyser\Checks\Code;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class DangerousSinksCheck implements Check
{
    private const DANGEROUS_FUNCTIONS = [
        'eval' => ['severity' => 'critical', 'description' => 'Executes arbitrary PHP code'],
        'unserialize' => ['severity' => 'critical', 'description' => 'Can trigger arbitrary object instantiation and magic method chains'],
        'extract' => ['severity' => 'high', 'description' => 'Overwrites local variables from user input'],
        'shell_exec' => ['severity' => 'critical', 'description' => 'Executes shell commands'],
        'exec' => ['severity' => 'critical', 'description' => 'Executes shell commands'],
        'system' => ['severity' => 'critical', 'description' => 'Executes shell commands'],
        'passthru' => ['severity' => 'critical', 'description' => 'Executes shell commands'],
        'proc_open' => ['severity' => 'critical', 'description' => 'Opens process for I/O'],
        'popen' => ['severity' => 'critical', 'description' => 'Opens process pipe'],
        'assert' => ['severity' => 'high', 'description' => 'Can execute arbitrary code if string assertions are enabled'],
        'preg_replace' => ['severity' => 'medium', 'description' => 'With /e modifier, executes code (deprecated but may exist in legacy code)'],
        'file_get_contents' => ['severity' => 'medium', 'description' => 'Can read arbitrary files or make SSRF requests'],
        'file_put_contents' => ['severity' => 'high', 'description' => 'Can write to arbitrary files'],
        'include' => ['severity' => 'critical', 'description' => 'Includes and executes arbitrary PHP files'],
        'require' => ['severity' => 'critical', 'description' => 'Includes and executes arbitrary PHP files'],
        'include_once' => ['severity' => 'critical', 'description' => 'Includes and executes arbitrary PHP files'],
        'require_once' => ['severity' => 'critical', 'description' => 'Includes and executes arbitrary PHP files'],
    ];

    public function id(): string
    {
        return 'SS003';
    }

    public function name(): string
    {
        return 'Dangerous Sinks with Tainted Input';
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

            // Check function calls
            $funcCalls = $nodeFinder->findInstanceOf($stmts, Node\Expr\FuncCall::class);
            foreach ($funcCalls as $call) {
                $funcName = $call->name instanceof Node\Name ? $call->name->toString() : null;
                if ($funcName === null || ! isset(self::DANGEROUS_FUNCTIONS[$funcName])) {
                    continue;
                }

                $info = self::DANGEROUS_FUNCTIONS[$funcName];

                // Check if any argument contains tainted input
                $hasTainted = false;
                foreach ($call->args as $arg) {
                    if ($this->containsTaintedInput($arg->value)) {
                        $hasTainted = true;
                        break;
                    }
                }

                if (! $hasTainted) {
                    continue;
                }

                $severity = match ($info['severity']) {
                    'critical' => Severity::Critical,
                    'high' => Severity::High,
                    default => Severity::Medium,
                };

                $className = $this->resolveSymbol($call, $stmts, $nodeFinder);

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $severity,
                    category: $this->category(),
                    message: "Call to {$funcName}() with potentially tainted input. {$info['description']}.",
                    file: $file,
                    line: $call->getStartLine(),
                    symbol: $className,
                    remediation: $this->getRemediation($funcName),
                );
            }

            // Check eval() - it's a language construct, not a function
            $evals = $nodeFinder->findInstanceOf($stmts, Node\Expr\Eval_::class);
            foreach ($evals as $evalNode) {
                if ($this->containsTaintedInput($evalNode->expr)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: Severity::Critical,
                        category: $this->category(),
                        message: 'Call to eval() with potentially tainted input. Executes arbitrary PHP code.',
                        file: $file,
                        line: $evalNode->getStartLine(),
                        symbol: $this->resolveSymbol($evalNode, $stmts, $nodeFinder),
                        remediation: 'Remove eval() usage. Use structured approaches like configuration arrays or strategy patterns instead.',
                    );
                }
            }

            // Check include/require expressions
            $includes = $nodeFinder->findInstanceOf($stmts, Node\Expr\Include_::class);
            foreach ($includes as $include) {
                if ($this->containsTaintedInput($include->expr)) {
                    $type = match ($include->type) {
                        Node\Expr\Include_::TYPE_INCLUDE => 'include',
                        Node\Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
                        Node\Expr\Include_::TYPE_REQUIRE => 'require',
                        Node\Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
                        default => 'include',
                    };

                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: Severity::Critical,
                        category: $this->category(),
                        message: "{$type} with potentially tainted input enables arbitrary file inclusion.",
                        file: $file,
                        line: $include->getStartLine(),
                        symbol: $this->resolveSymbol($include, $stmts, $nodeFinder),
                        remediation: 'Use a whitelist of allowed files instead of including user-controlled paths.',
                    );
                }
            }
        }
    }

    private function containsTaintedInput(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\FuncCall) {
            $name = $expr->name instanceof Node\Name ? $expr->name->toString() : null;
            if ($name === 'request') {
                return true;
            }
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            if ($expr->var instanceof Node\Expr\Variable && $expr->var->name === 'request') {
                return true;
            }
            if ($expr->var instanceof Node\Expr\FuncCall) {
                $name = $expr->var->name instanceof Node\Name ? $expr->var->name->toString() : null;
                if ($name === 'request') {
                    return true;
                }
            }
        }

        if ($expr instanceof Node\Expr\Variable) {
            $name = is_string($expr->name) ? $expr->name : null;
            if (in_array($name, ['request', '_GET', '_POST', '_REQUEST'], true)) {
                return true;
            }
        }

        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return $this->containsTaintedInput($expr->left) || $this->containsTaintedInput($expr->right);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Node\Expr && $this->containsTaintedInput($part)) {
                    return true;
                }
            }
        }

        if ($expr instanceof Node\Expr\ArrayDimFetch && $expr->var instanceof Node\Expr) {
            return $this->containsTaintedInput($expr->var);
        }

        return false;
    }

    private function resolveSymbol(Node\Expr $node, array $stmts, NodeFinder $nodeFinder): ?string
    {
        $classes = $nodeFinder->findInstanceOf($stmts, Node\Stmt\Class_::class);
        foreach ($classes as $class) {
            if ($node->getStartLine() >= $class->getStartLine() && $node->getEndLine() <= $class->getEndLine()) {
                return $class->namespacedName?->toString() ?? $class->name?->toString();
            }
        }

        return null;
    }

    private function getRemediation(string $funcName): string
    {
        return match ($funcName) {
            'eval' => 'Remove eval() usage. Use structured approaches like configuration arrays or strategy patterns instead.',
            'unserialize' => 'Use json_decode() instead, or pass allowed_classes option: unserialize($data, ["allowed_classes" => false])',
            'extract' => 'Access array values directly instead of extracting them into the local scope.',
            'shell_exec', 'exec', 'system', 'passthru', 'proc_open', 'popen' => 'Use Process component (symfony/process) with explicit argument escaping, or use escapeshellarg() for each argument.',
            'file_get_contents' => 'Validate and whitelist URLs/paths. For HTTP requests, use Http::get() with URL validation.',
            'file_put_contents' => 'Validate and whitelist file paths. Never use user input directly in file paths.',
            default => 'Avoid passing user-controlled input to this function.',
        };
    }
}
