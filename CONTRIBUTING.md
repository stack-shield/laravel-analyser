# Contributing to Stackshield Scanner

## Adding a New Check

1. Create a new class in the appropriate `src/Checks/{Category}/` directory
2. Implement the `Check` interface:

```php
<?php

namespace Stackshield\Scanner\Checks\Code;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class YourCheck implements Check
{
    public function id(): string { return 'SS0XX'; }
    public function name(): string { return 'Your Check Name'; }
    public function severity(): Severity { return Severity::Medium; }
    public function category(): Category { return Category::Code; }
    public function version(): int { return 1; }

    public function run(Context $ctx): iterable
    {
        // Your detection logic here
        // yield Finding instances for each issue found
    }
}
```

3. Register it in `ScannerServiceProvider::registerDefaultChecks()`
4. Add a test in `tests/Unit/ChecksTest.php`

## Guidelines

- Prefer false negatives over false positives. Users lose trust quickly if the scanner cries wolf.
- Each check should have a clear remediation message.
- Use `Context` methods (ast, phpFiles, env, composerJson, etc.) rather than direct filesystem access.
- Bump `version()` when changing detection logic — this resurfaces baselined findings.

## Running Tests

```bash
composer test
```

## Code Style

Follow PSR-12. Run `composer lint` before submitting.
