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

/** A throwaway app built from relative path => contents. */
function tempApp(array $files): Context
{
    $base = sys_get_temp_dir().'/analyser-'.bin2hex(random_bytes(6));
    foreach ($files as $path => $contents) {
        @mkdir(dirname("$base/$path"), 0777, true);
        file_put_contents("$base/$path", $contents);
    }

    return new Context($base);
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
it('detects debug tools in production require', function () {
    $ctx = tempApp(['composer.json' => json_encode(['require' => ['barryvdh/laravel-debugbar' => '^3.0']])]);

    $findings = iterator_to_array((new DevToolsProductionCheck)->run($ctx));

    expect($findings)->toHaveCount(1);
    expect($findings[0]->message)->toContain('Debugbar');
});

it('does not treat gated production dashboards as dev tools', function () {
    // The fixture requires Telescope in production, which ships behind a gate.
    expect(iterator_to_array((new DevToolsProductionCheck)->run(fixtureContext())))->toBeEmpty();
});

// SS015: Session Cookie
it('detects insecure session cookie settings', function () {
    $check = new SessionCookieCheck;
    $findings = iterator_to_array($check->run(fixtureContext()));

    $secureCookieFindings = array_filter($findings, fn ($f) => str_contains($f->message, 'SESSION_SECURE_COOKIE'));
    expect($secureCookieFindings)->not->toBeEmpty();
});

// SS001: Mass Assignment
it('does not flag models that rely on Eloquent default guarding', function () {
    $ctx = tempApp([
        'app/Models/Post.php' => '<?php class Post extends Model {}',
        'app/Http/Controllers/PostController.php' => '<?php class PostController { function store($request) { return Post::create($request->all()); } }',
    ]);

    expect(iterator_to_array((new MassAssignmentCheck)->run($ctx)))->toBeEmpty();
});

it('flags raw request data reaching an unguarded model', function () {
    $ctx = tempApp([
        'app/Models/Post.php' => '<?php class Post extends Model { protected $guarded = []; }',
        'app/Http/Controllers/PostController.php' => "<?php class PostController {\n function store(\$request) {\n return Post::create(\$request->all());\n }\n function update(\$request, \$post) { \$post->update(\$request->validated()); } }",
    ]);

    $findings = iterator_to_array((new MassAssignmentCheck)->run($ctx));

    expect($findings)->toHaveCount(1);
    expect($findings[0]->line)->toBe(3);
    expect($findings[0]->message)->toContain('Post');
});

it('flags forceFill with raw request data even when models are guarded', function () {
    $ctx = tempApp([
        'app/Http/Controllers/UserController.php' => '<?php class UserController { function update($user) { $user->forceFill(request()->all())->save(); } }',
    ]);

    expect(iterator_to_array((new MassAssignmentCheck)->run($ctx)))->toHaveCount(1);
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

// SS050: throttling applied to the api group counts
it('accepts api throttling configured in bootstrap/app.php', function () {
    $ctx = tempApp([
        'routes/api.php' => "<?php Route::get('/users', fn () => 1);",
        'bootstrap/app.php' => '<?php return Application::configure()->withMiddleware(function ($middleware) { $middleware->throttleApi(); });',
    ]);

    expect(iterator_to_array((new \StackShield\Analyser\Checks\Routes\ApiRateLimitCheck)->run($ctx)))->toBeEmpty();
});

it('reports an unthrottled api once, not per route', function () {
    $ctx = tempApp(['routes/api.php' => "<?php Route::get('/a', fn () => 1);\nRoute::post('/b', fn () => 1);"]);

    expect(iterator_to_array((new \StackShield\Analyser\Checks\Routes\ApiRateLimitCheck)->run($ctx)))->toHaveCount(1);
});

// SS004: group middleware and throttling in code count
it('accepts auth routes inside a throttled group', function () {
    $ctx = tempApp(['routes/web.php' => "<?php Route::middleware('throttle:6,1')->group(function () { Route::post('login', [LoginController::class, 'store']); });"]);

    expect(iterator_to_array((new AuthThrottleCheck)->run($ctx)))->toBeEmpty();
});

it('accepts login throttled in a Breeze-style LoginRequest', function () {
    $ctx = tempApp([
        'routes/auth.php' => "<?php Route::post('login', [AuthenticatedSessionController::class, 'store']);",
        'app/Http/Requests/Auth/LoginRequest.php' => '<?php class LoginRequest { public function authenticate() { $this->ensureIsNotRateLimited(); } }',
    ]);

    expect(iterator_to_array((new AuthThrottleCheck)->run($ctx)))->toBeEmpty();
});

// SS044: literal-only expressions and request data
it('ignores raw output that can only render string literals', function () {
    $ctx = tempApp(['resources/views/nav.blade.php' => "<li{!! request()->is('users*') ? ' class=\"active\"' : '' !!}>"]);

    expect(iterator_to_array((new \StackShield\Analyser\Checks\Code\BladeRawOutputCheck)->run($ctx)))->toBeEmpty();
});

it('grades raw output of request data and marks named variables advisory', function () {
    $ctx = tempApp(['resources/views/search.blade.php' => "{!! request('q') !!}\n{!! \$content !!}"]);

    $findings = iterator_to_array((new \StackShield\Analyser\Checks\Code\BladeRawOutputCheck)->run($ctx), false);

    expect($findings)->toHaveCount(2);
    expect($findings[0]->advisory)->toBeFalse();
    expect($findings[1]->advisory)->toBeTrue();
});

// SS006: external callbacks are not findings
it('does not flag CSRF exemptions for webhooks', function () {
    $ctx = tempApp(['bootstrap/app.php' => "<?php \$middleware->validateCsrfTokens(except: ['stripe/*', 'webhooks/github']);"]);

    expect(iterator_to_array((new CsrfExemptionCheck)->run($ctx)))->toBeEmpty();
});

// SS010: an empty key in a committed template is fine, a real one is not
it('flags a real APP_KEY committed to a repository', function () {
    $base = sys_get_temp_dir().'/analyser-'.bin2hex(random_bytes(6));
    mkdir($base);
    file_put_contents("$base/.env.production", 'APP_KEY=base64:'.base64_encode(random_bytes(32)));
    file_put_contents("$base/.env", 'APP_KEY=');

    $findings = iterator_to_array((new AppKeyCheck)->run(new Context($base, ['source' => 'repository'])), false);

    expect($findings)->toHaveCount(1);
    expect($findings[0]->file)->toBe('.env.production');
});
