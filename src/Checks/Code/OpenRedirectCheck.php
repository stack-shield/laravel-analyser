<?php

namespace StackShield\Analyser\Checks\Code;

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

class OpenRedirectCheck implements Check
{
    private const REDIRECT_PATTERNS = [
        '/redirect\s*\(\s*\$request\s*->\s*(?:input|get|query)\s*\(/' => 'redirect() with $request->input/get/query',
        '/redirect\s*\(\s*request\s*\(\s*[\'"]/' => 'redirect() with request() helper',
        '/Redirect\s*::\s*to\s*\(\s*\$request\s*->\s*(?:input|get|query)\s*\(/' => 'Redirect::to() with $request->input/get/query',
        '/redirect\s*\(\s*\$_GET\s*\[/' => 'redirect() with $_GET',
        '/redirect\s*\(\s*\$_REQUEST\s*\[/' => 'redirect() with $_REQUEST',
        '/redirect\s*\(\s*\$request\s*->\s*url\b/' => 'redirect() with $request->url',
        '/redirect\s*\(\s*\$request\s*\[\s*[\'"]/' => 'redirect() with $request[] array access',
        '/return\s+redirect\s*\(\s*\$request\s*->\s*(?:input|get|query)\s*\(/' => 'return redirect() with user input',
    ];

    public function id(): string
    {
        return 'SS041';
    }

    public function name(): string
    {
        return 'Open Redirect';
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
        foreach ($ctx->phpFiles('app') as $file) {
            $contents = $ctx->fileContents($file);
            if ($contents === null) {
                continue;
            }

            $lines = explode("\n", $contents);

            foreach ($lines as $lineNum => $line) {
                $trimmed = trim($line);
                if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#') || str_starts_with($trimmed, '*')) {
                    continue;
                }

                foreach (self::REDIRECT_PATTERNS as $pattern => $description) {
                    if (preg_match($pattern, $line)) {
                        yield new Finding(
                            checkId: $this->id(),
                            checkName: $this->name(),
                            checkVersion: $this->version(),
                            severity: $this->severity(),
                            category: $this->category(),
                            message: "Potential open redirect: {$description}. User-controlled input is passed directly to a redirect, allowing attackers to redirect users to malicious sites.",
                            file: $file,
                            line: $lineNum + 1,
                            snippet: trim($line),
                            remediation: 'Validate the redirect URL against an allowlist of trusted domains, or use a relative path. Consider using redirect()->intended() or URL::isValidUrl() with domain checks.',
                        );

                        break; // One finding per line
                    }
                }
            }
        }
    }
}
