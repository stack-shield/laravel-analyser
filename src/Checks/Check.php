<?php

namespace StackShield\Analyser\Checks;

use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;

interface Check
{
    public function id(): string;

    public function name(): string;

    public function severity(): Severity;

    public function category(): Category;

    public function version(): int;

    /** @return iterable<\StackShield\Analyser\Finding> */
    public function run(Context $ctx): iterable;
}
