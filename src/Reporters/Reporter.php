<?php

namespace Stackshield\Scanner\Reporters;

use Stackshield\Scanner\Report;

interface Reporter
{
    public function render(Report $report): string;
}
