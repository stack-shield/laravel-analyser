<?php

namespace Stackshield\Scanner\Checks\Filesystem;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class ExposedFilesCheck implements Check
{
    private const DANGEROUS_FILES = [
        '.env' => 'Environment file contains secrets (APP_KEY, database credentials, API keys)',
        '.env.backup' => 'Environment backup file contains secrets',
        '.env.save' => 'Environment save file contains secrets',
        '.env.old' => 'Old environment file contains secrets',
        '.git/config' => 'Git config exposes repository information and potentially credentials',
        '.git/HEAD' => 'Git HEAD file indicates git repository is publicly accessible',
    ];

    public function id(): string
    {
        return 'SS020';
    }

    public function name(): string
    {
        return 'Exposed Sensitive Files';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function category(): Category
    {
        return Category::Filesystem;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        foreach (self::DANGEROUS_FILES as $file => $description) {
            $publicPath = 'public/'.$file;

            if ($ctx->fileExists($publicPath)) {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: $this->severity(),
                    category: $this->category(),
                    message: "{$file} is accessible under the public web root. {$description}.",
                    file: $publicPath,
                    symbol: $file,
                    remediation: "Remove {$file} from the public/ directory. Sensitive files should never be in the web root.",
                );
            }
        }
    }
}
