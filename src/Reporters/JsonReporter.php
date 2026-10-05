<?php

namespace StackShield\Analyser\Reporters;

use StackShield\Analyser\Report;

final class JsonReporter implements Reporter
{
    public function render(Report $report): string
    {
        return json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
