<?php

namespace Stackshield\Scanner\Commands;

use Illuminate\Console\Command;
use Stackshield\Scanner\Scanner;

class ChecksCommand extends Command
{
    protected $signature = 'stackshield:checks';

    protected $description = 'List all registered checks';

    public function handle(Scanner $scanner): int
    {
        $checks = $scanner->checks();

        if (empty($checks)) {
            $this->warn('No checks registered.');

            return self::SUCCESS;
        }

        $rows = [];
        foreach ($checks as $check) {
            $rows[] = [
                $check->id(),
                $check->name(),
                $check->severity()->label(),
                $check->category()->label(),
                'v'.$check->version(),
            ];
        }

        $this->table(['ID', 'Name', 'Severity', 'Category', 'Version'], $rows);

        return self::SUCCESS;
    }
}
