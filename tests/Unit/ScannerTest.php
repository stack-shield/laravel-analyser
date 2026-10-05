<?php

use StackShield\Analyser\Checks\Check;
use StackShield\Analyser\Context;
use StackShield\Analyser\Enums\Category;
use StackShield\Analyser\Enums\Severity;
use StackShield\Analyser\Finding;
use StackShield\Analyser\Scanner;

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

it('leaves advisory findings out of the grade', function () {
    $scanner = new Scanner;
    $scanner->registerCheck(new class implements \StackShield\Analyser\Checks\Advisory, Check {
        public function id(): string { return 'TEST002'; }
        public function name(): string { return 'Heuristic'; }
        public function severity(): Severity { return Severity::Critical; }
        public function category(): Category { return Category::Code; }
        public function version(): int { return 1; }
        public function run(Context $ctx): iterable {
            yield new Finding('TEST002', 'Heuristic', 1, Severity::Critical, Category::Code, 'Maybe', 'a.php');
        }
    });

    $report = $scanner->scan(__DIR__.'/../Fixtures/laravel-app');

    expect($report->grade())->toBe('A');
    expect($report->toArray()['advisory_counts']['critical'])->toBe(1);
    expect($report->toArray()['findings'][0]['advisory'])->toBeTrue();
});

it('skips files that do not parse instead of aborting the scan', function () {
    $base = sys_get_temp_dir().'/analyser-'.bin2hex(random_bytes(6));
    mkdir("$base/routes", 0777, true);
    file_put_contents("$base/routes/web.php", '<?php Route::post("login", function () {');

    $report = Scanner::withDefaultChecks(['offline' => true])->scan($base);

    expect($report->unparseableFiles())->toBe(['routes/web.php']);
});
