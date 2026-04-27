<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class BroadcastingAuthCheck implements Check
{
    public function id(): string
    {
        return 'SS046';
    }

    public function name(): string
    {
        return 'Broadcasting Channel Authorization';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        $channelsFile = 'routes/channels.php';
        $contents = $ctx->fileContents($channelsFile);

        if ($contents === null) {
            return;
        }

        $lines = explode("\n", $contents);
        $inChannel = false;
        $channelStartLine = 0;
        $braceDepth = 0;
        $channelSnippet = '';

        foreach ($lines as $lineNum => $line) {
            // Detect channel definitions that simply return true
            if (preg_match('/Broadcast\s*::\s*channel\s*\(/', $line)) {
                // Check for inline return true pattern
                if (preg_match('/function\s*\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}/', $line)
                    || preg_match('/function\s*\([^)]*\)\s*=>\s*true/', $line)
                    || preg_match('/fn\s*\([^)]*\)\s*=>\s*true/', $line)) {
                    yield new Finding(
                        checkId: $this->id(),
                        checkName: $this->name(),
                        checkVersion: $this->version(),
                        severity: $this->severity(),
                        category: $this->category(),
                        message: 'Broadcasting channel authorization callback returns true without checking user permissions. Any authenticated user can subscribe to this channel.',
                        file: $channelsFile,
                        line: $lineNum + 1,
                        symbol: 'Broadcast::channel',
                        snippet: trim($line),
                        remediation: 'Add proper authorization logic to the channel callback. Verify the authenticated user has permission to access the channel (e.g., return $user->id === $id).',
                    );
                }
            }
        }
    }
}
