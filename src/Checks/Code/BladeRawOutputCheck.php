<?php

namespace StackShield\Analyser\Checks\Code;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class BladeRawOutputCheck implements Check
{
    /** Request data rendered raw: graded. */
    private const REQUEST_SOURCES = [
        '$request', 'request(', 'Request::', 'old(', '$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
    ];

    /**
     * Names that often hold user content, but whose source static analysis
     * cannot see: reported as advisory, not graded.
     */
    private const SUSPICIOUS_VARIABLES = [
        '$input', '$query', '$name', '$title', '$body',
        '$content', '$message', '$comment', '$description',
    ];

    public function id(): string
    {
        return 'SS044';
    }

    public function name(): string
    {
        return 'Blade Raw Output with User Data';
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
        return 2;
    }

    public function run(Context $ctx): iterable
    {
        $viewsPath = $ctx->resolve('resources/views');
        if (! is_dir($viewsPath)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($viewsPath, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        /** @var SplFileInfo $fileInfo */
        foreach ($iterator as $fileInfo) {
            if (! $fileInfo->isFile() || ! str_ends_with($fileInfo->getFilename(), '.blade.php')) {
                continue;
            }

            $file = $ctx->relativize($fileInfo->getRealPath());
            $contents = $ctx->fileContents($file);
            if ($contents === null) {
                continue;
            }

            $lines = explode("\n", $contents);

            foreach ($lines as $lineNum => $line) {
                // Match {!! ... !!} raw output
                if (! preg_match('/\{!!\s*(.+?)\s*!!\}/', $line, $matches)) {
                    continue;
                }

                $expression = $matches[1];

                if ($this->rendersOnlyLiterals($expression)) {
                    continue;
                }

                // request()->user() is the authenticated model, not input.
                $inputs = preg_replace('/(?:request\(\)|\$request|Request::)\s*(?:->|::)?user\(\)/', '', $expression);
                $fromRequest = $this->containsAny($inputs, self::REQUEST_SOURCES);
                if (! $fromRequest && ! $this->containsAny($expression, self::SUSPICIOUS_VARIABLES)) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: $fromRequest
                        ? 'Request data is rendered with Blade raw output {!! !!}, without escaping. This is a cross-site scripting (XSS) vulnerability.'
                        : 'Blade raw output {!! !!} renders a variable that may hold user content. If it does, this is a cross-site scripting (XSS) risk.',
                    file: $file,
                    line: $lineNum + 1,
                    snippet: trim($line),
                    remediation: 'Use {{ }} for escaped output instead of {!! !!}. If raw HTML is required, sanitize the data first with e() or a library like HTMLPurifier.',
                    advisory: ! $fromRequest,
                );
            }
        }
    }

    /**
     * Expressions that cannot output unescaped input: a ternary choosing
     * between string literals (request()->is('x*') ? ' class="active"' : ''),
     * or a helper that escapes what it renders.
     */
    private function rendersOnlyLiterals(string $expression): bool
    {
        $literal = '(?:\'[^\']*\'|"[^"]*")';
        if (preg_match('/\?\s*'.$literal.'\s*:\s*'.$literal.'\s*\)?\s*$/', $expression)) {
            return true;
        }

        // Paginator markup, Fortify's QR code, and form builders (Laravel
        // Collective, spatie/laravel-html), which escape the values they render.
        return (bool) preg_match('/->(?:links|render|appends)\(|QrCodeSvg\(\)|^\s*(?:Form|Html|html\(\))\s*(?:::|->)/', $expression);
    }

    /** @param string[] $needles */
    private function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (str_contains($haystack, $needle)) {
                return true;
            }
        }

        return false;
    }
}
