<?php

namespace StackShield\Analyser\Checks\Code;

use PhpParser\Node;
use PhpParser\NodeFinder;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class FileUploadCheck implements Check
{
    private const STORE_METHODS = ['store', 'storeAs', 'move', 'storePublicly', 'storePubliclyAs'];

    /** File type validation: rules, Rule/File objects, or explicit MIME and extension checks. */
    private const TYPE_VALIDATION = '/mimes:|mimetypes:|[\'"|]image[\'"|:]|extensions:|File::(?:image|types)|Rule::imageFile|dimensions:|getMimeType\(|getClientMimeType\(|guessExtension\(|allowed_?(?:extensions|types|mimes)|\bmimeType\(/i';

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
        return 2;
    }

    /**
     * An upload becomes code execution when it lands somewhere the web server
     * serves and nothing restricts its type. Uploads to private disks, or
     * validated in the method, its class, or a form request the method takes,
     * are not reported.
     */
    public function run(Context $ctx): iterable
    {
        $finder = new NodeFinder;

        foreach ($ctx->phpFiles('app') as $file) {
            $stmts = $ctx->ast($file);
            $source = $ctx->fileContents($file) ?? '';

            foreach ($finder->findInstanceOf($stmts, Node\Stmt\ClassMethod::class) as $method) {
                foreach ($finder->findInstanceOf($method->stmts ?? [], Node\Expr\MethodCall::class) as $call) {
                    if (! $call->name instanceof Node\Identifier || ! in_array($call->name->toString(), self::STORE_METHODS, true)) {
                        continue;
                    }
                    if (! $this->isOnUploadedFile($call) || ! $this->isPublicDestination($call)) {
                        continue;
                    }
                    if ($this->isValidated($ctx, $method, $source)) {
                        continue;
                    }

                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: "An uploaded file is written to a publicly served location with {$call->name->toString()}() and its type is never validated. An attacker can upload a .php file and run it on the server.",
                        file: $file,
                        line: $call->getStartLine(),
                        symbol: $method->name->toString(),
                        remediation: "Validate the type before storing, e.g. ['file' => 'required|file|mimes:jpg,png,pdf|max:10240'], and keep uploads on a private disk served through a controller.",
                    );
                }
            }
        }
    }

    private function isOnUploadedFile(Node\Expr\MethodCall $call): bool
    {
        if ($call->var instanceof Node\Expr\MethodCall && $call->var->name instanceof Node\Identifier && $call->var->name->toString() === 'file') {
            return true;
        }

        return $call->var instanceof Node\Expr\Variable && is_string($call->var->name)
            && preg_match('/file|upload|image|photo|avatar|logo|attachment|banner|document/i', $call->var->name);
    }

    /** storePublicly(), the public disk, public_path(), or a web-served folder under base_path(). */
    private function isPublicDestination(Node\Expr\MethodCall $call): bool
    {
        $method = $call->name->toString();
        if (in_array($method, ['storePublicly', 'storePubliclyAs'], true)) {
            return true;
        }

        $finder = new NodeFinder;
        foreach ($call->getRawArgs() as $index => $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }
            $strings = array_map(fn (Node\Scalar\String_ $s) => $s->value, $finder->findInstanceOf($arg->value, Node\Scalar\String_::class));
            $functions = array_map(fn (Node\Expr\FuncCall $f) => $f->name instanceof Node\Name ? $f->name->toString() : '', $finder->findInstanceOf($arg->value, Node\Expr\FuncCall::class));

            if ($method === 'move' && $index === 0) {
                if (in_array('public_path', $functions, true)) {
                    return true;
                }
                if (in_array('base_path', $functions, true) && preg_grep('/^\/?(?:public|assets|uploads|img|images|media)\b/i', $strings)) {
                    return true;
                }
            }
            // store('avatars', 'public') / storeAs($dir, $name, ['disk' => 'public'])
            if ($method !== 'move' && $index > 0 && in_array('public', $strings, true)) {
                return true;
            }
        }

        return false;
    }

    private function isValidated(Context $ctx, Node\Stmt\ClassMethod $method, string $classSource): bool
    {
        // In the class: the method itself, rules(), Livewire $rules or #[Validate].
        if (preg_match(self::TYPE_VALIDATION, $classSource)) {
            return true;
        }

        // In a form request the method type-hints.
        foreach ($method->params as $param) {
            $type = $param->type instanceof Node\Name ? $param->type->toString() : null;
            if ($type === null || in_array($type, ['Illuminate\\Http\\Request', 'Request'], true)) {
                continue;
            }
            $file = $ctx->classFile($type);
            if ($file !== null && preg_match(self::TYPE_VALIDATION, $ctx->fileContents($file) ?? '')) {
                return true;
            }
        }

        return false;
    }
}
