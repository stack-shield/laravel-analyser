<?php

use StackShield\Analyser\Context;

it('keeps parsing correctly once the syntax tree cache is full', function () {
    $dir = sys_get_temp_dir().'/analyser-context-'.bin2hex(random_bytes(4));
    mkdir($dir.'/app', 0777, true);
    for ($i = 0; $i < 150; $i++) {
        file_put_contents("{$dir}/app/C{$i}.php", "<?php\nnamespace App;\nclass C{$i} { public function run() { return {$i}; } }\n");
    }

    $context = new Context($dir);
    $first = $context->ast('app/C0.php');
    foreach (range(1, 149) as $i) {
        $context->ast("app/C{$i}.php");
    }

    // C0 has been evicted and is parsed again, to the same tree.
    expect($context->ast('app/C0.php'))->toEqual($first)
        ->and($context->ast('app/C0.php')[0]->stmts[0]->name->toString())->toBe('C0');

    array_map('unlink', glob($dir.'/app/*.php'));
    rmdir($dir.'/app');
    rmdir($dir);
});
