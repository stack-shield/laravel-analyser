<?php

use StackShield\Analyser\Checks\Code\DangerousSinksCheck;
use StackShield\Analyser\Checks\Code\MassAssignmentCheck;
use StackShield\Analyser\Checks\Code\RawSqlCheck;
use StackShield\Analyser\Checks\Config\AppKeyCheck;
use StackShield\Analyser\Checks\Config\DebugModeCheck;
use StackShield\Analyser\Checks\Config\DevToolsProductionCheck;
use StackShield\Analyser\Checks\Config\SessionCookieCheck;
use StackShield\Analyser\Checks\Filesystem\ExposedFilesCheck;
use StackShield\Analyser\Checks\Routes\AuthThrottleCheck;
use StackShield\Analyser\Checks\Routes\CsrfExemptionCheck;
use StackShield\Analyser\Checks\Routes\RouteModelBindingAuthCheck;
use StackShield\Analyser\Context;

function fixtureContext(): Context
{
    return new Context(__DIR__.'/../Fixtures/laravel-app');
}

// SS012: Debug Mode
it('detects APP_DEBUG=true in production env', function () {
    $check = new DebugModeCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    expect($findings)->not->toBeEmpty();
    expect($findings[0]->checkId)->toBe('SS012');
    expect($findings[0]->file)->toBe('.env.production');
});

// SS010: APP_KEY
it('detects short APP_KEY', function () {
    $check = new AppKeyCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    // .env.production has APP_KEY=base64:short which decodes to only 5 bytes
    $shortKeyFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'too short'));
    expect($shortKeyFindings)->not->toBeEmpty();
});

// SS013: Dev Tools
it('detects dev tools in production require', function () {
    $check = new DevToolsProductionCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    expect($findings)->not->toBeEmpty();
    $telescopeFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'Telescope'));
    expect($telescopeFindings)->not->toBeEmpty();
});

// SS015: Session Cookie
it('detects insecure session cookie settings', function () {
    $check = new SessionCookieCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    $secureCookieFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'SESSION_SECURE_COOKIE'));
    expect($secureCookieFindings)->not->toBeEmpty();
});

// SS001: Mass Assignment
it('detects models without fillable or guarded', function () {
    $check = new MassAssignmentCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    expect($findings)->not->toBeEmpty();
    // Post model has no $fillable/$guarded
    $postFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'Post'));
    expect($postFindings)->not->toBeEmpty();

    // User model has $fillable - should not be flagged
    $userFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'User'));
    expect($userFindings)->toBeEmpty();
});

// SS020: Exposed Files
it('does not flag when no files in public', function () {
    $check = new ExposedFilesCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    // Fixture doesn't have .env in public/
    expect($findings)->toBeEmpty();
});

// SS004: Auth Throttle
it('detects auth routes without throttle', function () {
    $check = new AuthThrottleCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    expect($findings)->not->toBeEmpty();
    $loginFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'login'));
    expect($loginFindings)->not->toBeEmpty();
});

// SS005: Route Model Binding
it('detects route model binding without auth', function () {
    $check = new RouteModelBindingAuthCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    expect($findings)->not->toBeEmpty();
    // /users/{user}/orders has no auth middleware
    $orderFindings = array_filter($findings, fn ($f) => str_contains($f->symbol ?? '', 'users'));
    expect($orderFindings)->not->toBeEmpty();
});

// SS006: CSRF Exemptions
it('detects CSRF exemptions', function () {
    $check = new CsrfExemptionCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    expect($findings)->not->toBeEmpty();
    // api/* is a broad exemption
    $broadFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'api/*'));
    expect($broadFindings)->not->toBeEmpty();
});

// SS002: Raw SQL
it('detects raw SQL with tainted input', function () {
    $check = new RawSqlCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    expect($findings)->not->toBeEmpty();
    expect($findings[0]->checkId)->toBe('SS002');
});

// SS003: Dangerous Sinks
it('detects dangerous function calls with tainted input', function () {
    $check = new DangerousSinksCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    expect($findings)->not->toBeEmpty();
    $evalFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'eval'));
    $shellFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'shell_exec'));
    expect($evalFindings)->not->toBeEmpty();
    expect($shellFindings)->not->toBeEmpty();
});
