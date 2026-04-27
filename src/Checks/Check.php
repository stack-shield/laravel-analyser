<?php

namespace Stackshield\Scanner\Checks;

use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;

interface Check
{
    public function id(): string;

    public function name(): string;

    public function severity(): Severity;

    public function category(): Category;

    public function version(): int;

    /** @return iterable<\Stackshield\Scanner\Finding> */
    public function run(Context $ctx): iterable;
}
