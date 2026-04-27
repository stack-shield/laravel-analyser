<?php

namespace Stackshield\Scanner\Tests;

use Orchestra\Testbench\TestCase as BaseTestCase;
use Stackshield\Scanner\ScannerServiceProvider;

abstract class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [ScannerServiceProvider::class];
    }
}
