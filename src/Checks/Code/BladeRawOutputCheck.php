<?php

namespace Stackshield\Scanner\Checks\Code;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class BladeRawOutputCheck implements Check
{
    private const SUSPICIOUS_VARIABLES = [
        '$request', 'request(', '$_GET', '$_POST', '$_REQUEST',
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
        return 1;
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

                // Check if the expression contains potentially user-controllable data
                foreach (self::SUSPICIOUS_VARIABLES as $var) {
                    if (str_contains($expression, $var)) {
                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $this->severity(),
                            category: $this->category(),
                            message: "Blade raw output {!! !!} may render user-controllable data without escaping, leading to XSS vulnerabilities.",
                            file: $file,
                            line: $lineNum + 1,
                            snippet: trim($line),
                            remediation: 'Use {{ }} for escaped output instead of {!! !!}. If raw HTML is required, sanitize the data first with e() or a library like HTMLPurifier.',
                        );

                        break; // One finding per line
                    }
                }
            }
        }
    }
}
