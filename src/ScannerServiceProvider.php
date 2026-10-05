<?php

namespace StackShield\Analyser;

use Illuminate\Support\ServiceProvider;
use StackShield\Analyser\Commands\BaselineCommand;
use StackShield\Analyser\Commands\ChecksCommand;
use StackShield\Analyser\Commands\FixCommand;
use StackShield\Analyser\Commands\ReportCommand;
use StackShield\Analyser\Commands\ScanCommand;
use Symfony\Component\Yaml\Yaml;

class ScannerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Scanner::class, function () {
            return Scanner::withDefaultChecks($this->loadConfig());
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                ScanCommand::class,
                BaselineCommand::class,
                ChecksCommand::class,
                ReportCommand::class,
                FixCommand::class,
            ]);
        }
    }

    private function loadConfig(): array
    {
        $configPath = base_path('stackshield.yaml');
        if (! file_exists($configPath)) {
            return [];
        }

        return Yaml::parseFile($configPath) ?? [];
    }
}
