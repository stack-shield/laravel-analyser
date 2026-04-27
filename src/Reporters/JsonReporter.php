<?php

namespace Stackshield\Scanner\Reporters;

use Stackshield\Scanner\Report;

final class JsonReporter implements Reporter
{
    public function render(Report $report): string
    {
        return json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
