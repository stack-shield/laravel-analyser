<?php

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;
use Stackshield\Scanner\Scanner;

it('runs with no checks registered', function () {
    $scanner = new Scanner;
    $report = $scanner->scan(__DIR__.'/../Fixtures/laravel-app');

    expect($report->count())->toBe(0);
    expect($report->grade())->toBe('A');
});

it('registers and runs checks', function () {
    $scanner = new Scanner;
    $check = new class implements Check {
        public function id(): string { return 'TEST001'; }
        public function name(): string { return 'Test Check'; }
        public function severity(): Severity { return Severity::Medium; }
        public function category(): Category { return Category::Config; }
        public function version(): int { return 1; }
        public function run(Context $ctx): iterable {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: 'Test finding',
                file: 'test.php',
                line: 1,
            );
        }
    };

    $scanner->registerCheck($check);
    $report = $scanner->scan(__DIR__.'/../Fixtures/laravel-app');

    expect($report->count())->toBe(1);
    expect($report->findings()[0]->checkId)->toBe('TEST001');
});

it('respects disabled checks in config', function () {
    $scanner = new Scanner(['checks' => ['TEST001' => ['enabled' => false]]]);
    $check = new class implements Check {
        public function id(): string { return 'TEST001'; }
        public function name(): string { return 'Test Check'; }
        public function severity(): Severity { return Severity::Medium; }
        public function category(): Category { return Category::Config; }
        public function version(): int { return 1; }
        public function run(Context $ctx): iterable {
            yield new Finding(
                checkId: $this->id(),
                checkName: $this->name(),
                checkVersion: $this->version(),
                severity: $this->severity(),
                category: $this->category(),
                message: 'Test',
                file: 'test.php',
            );
        }
    };

    $scanner->registerCheck($check);
    $report = $scanner->scan(__DIR__.'/../Fixtures/laravel-app');

    expect($report->count())->toBe(0);
});
