<?php

namespace StackShield\Analyser\Tests;

use Orchestra\Testbench\TestCase as BaseTestCase;
use StackShield\Analyser\ScannerServiceProvider;

abstract class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [ScannerServiceProvider::class];
    }
}
