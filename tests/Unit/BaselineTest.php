<?php

use StackShield\Analyser\Baseline\Baseline;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;

it('generates baseline from findings', function () {
    $finding = new Finding(
        checkId: 'SS012',
        checkName: 'Debug Mode',
        checkVersion: 1,
        severity: Severity::High,
        category: Category::Config,
        message: 'Test',
        file: '.env.production',
        symbol: 'APP_DEBUG',
    );

    $data = Baseline::generate([$finding]);

    expect($data['version'])->toBe(1);
    expect($data['findings'])->toHaveCount(1);
    expect($data['findings'][0]['fingerprint'])->toBe($finding->fingerprint);
    expect($data['findings'][0]['check'])->toBe('SS012');
});

it('suppresses baselined findings', function () {
    $finding = new Finding(
        checkId: 'SS012',
        checkName: 'Debug Mode',
        checkVersion: 1,
        severity: Severity::High,
        category: Category::Config,
        message: 'Test',
        file: '.env.production',
        symbol: 'APP_DEBUG',
    );

    $baseline = new Baseline([
        [
            'fingerprint' => $finding->fingerprint,
            'check' => 'SS012',
            'check_version' => 1,
            'file' => '.env.production',
        ],
    ]);

    expect($baseline->isSuppressed($finding))->toBeTrue();
});

it('does not suppress findings with bumped check version', function () {
    $finding = new Finding(
        checkId: 'SS012',
        checkName: 'Debug Mode',
        checkVersion: 2,
        severity: Severity::High,
        category: Category::Config,
        message: 'Test',
        file: '.env.production',
        symbol: 'APP_DEBUG',
    );

    $baseline = new Baseline([
        [
            'fingerprint' => $finding->fingerprint,
            'check' => 'SS012',
            'check_version' => 1,
            'file' => '.env.production',
        ],
    ]);

    expect($baseline->isSuppressed($finding))->toBeFalse();
});

it('writes and reads baseline file', function () {
    $finding = new Finding(
        checkId: 'SS012',
        checkName: 'Debug Mode',
        checkVersion: 1,
        severity: Severity::High,
        category: Category::Config,
        message: 'Test',
        file: '.env.production',
        symbol: 'APP_DEBUG',
    );

    $path = sys_get_temp_dir().'/stackshield-test-baseline.yaml';
    Baseline::write($path, [$finding]);

    expect(file_exists($path))->toBeTrue();

    $loaded = Baseline::fromFile($path);
    expect($loaded->count())->toBe(1);
    expect($loaded->isSuppressed($finding))->toBeTrue();

    @unlink($path);
});
