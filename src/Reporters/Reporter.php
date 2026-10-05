<?php

namespace StackShield\Analyser\Reporters;

use StackShield\Analyser\Report;

interface Reporter
{
    public function render(Report $report): string;
}
