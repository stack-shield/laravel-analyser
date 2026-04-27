<?php

namespace Stackshield\Scanner\Baseline;

final class Fingerprint
{
    public static function generate(
        string $checkId,
        string $file,
        ?string $symbol,
        ?string $snippet,
    ): string {
        $snippetHash = $snippet ? sha1(self::normalizeSnippet($snippet)) : '';

        return sha1(implode("\0", [
            $checkId,
            self::normalizePath($file),
            $symbol ?? '',
            $snippetHash,
        ]));
    }

    private static function normalizePath(string $path): string
    {
        return ltrim(str_replace('\\', '/', $path), '/');
    }

    private static function normalizeSnippet(string $snippet): string
    {
        // Strip comments and normalize whitespace for stable fingerprints
        $snippet = preg_replace('#/\*.*?\*/#s', '', $snippet);
        $snippet = preg_replace('#//[^\n]*#', '', $snippet);
        $snippet = preg_replace('#\s+#', ' ', $snippet);

        return trim($snippet);
    }
}
