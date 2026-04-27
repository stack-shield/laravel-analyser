<?php

namespace Stackshield\Scanner\Checks\Code;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class MassAssignmentCheck implements Check
{
    public function id(): string
    {
        return 'SS001';
    }

    public function name(): string
    {
        return 'Mass Assignment';
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

        foreach ($ctx->phpFiles('app/Models') as $file) {
            $stmts = $ctx->ast($file);
            if (empty($stmts)) {
                continue;
            }

            $classes = $nodeFinder->findInstanceOf($stmts, Node\Stmt\Class_::class);

            foreach ($classes as $class) {
                if (! $this->extendsModel($class)) {
                    continue;
                }

                $hasFillable = false;
                $hasGuarded = false;

                foreach ($class->stmts as $stmt) {
                    if ($stmt instanceof Node\Stmt\Property) {
                        foreach ($stmt->props as $prop) {
                            if ($prop->name->toString() === 'fillable') {
                                $hasFillable = true;
                            }
                            if ($prop->name->toString() === 'guarded') {
                                $hasGuarded = true;
                            }
                        }
                    }
                }

                if (! $hasFillable && ! $hasGuarded) {
                    $className = $class->namespacedName?->toString() ?? $class->name?->toString() ?? 'Unknown';

                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: "Model {$className} has no \$fillable or \$guarded property. All attributes are mass-assignable by default.",
                        file: $file,
                        line: $class->getStartLine(),
                        symbol: $className,
                        snippet: "class {$class->name->toString()} extends Model",
                        remediation: "Add a \$fillable array listing only the attributes that should be mass-assignable, or set \$guarded = ['*'] to guard all attributes.",
                    );
                }
            }
        }
    }

    private function extendsModel(Node\Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        $parent = $class->extends->toString();
        $parentParts = explode('\\', $parent);
        $shortName = end($parentParts);

        return in_array($parent, [
            'Model',
            'Illuminate\\Database\\Eloquent\\Model',
            'Authenticatable',
            'Illuminate\\Foundation\\Auth\\User',
        ], true) || in_array($shortName, ['Model', 'Authenticatable'], true);
    }
}
