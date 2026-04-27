<?php

use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;
use Stackshield\Scanner\Reporters\ConsoleReporter;
use Stackshield\Scanner\Reporters\JsonReporter;
use Stackshield\Scanner\Reporters\MarkdownReporter;
use Stackshield\Scanner\Reporters\SarifReporter;
use Stackshield\Scanner\Report;

function createTestReport(): Report
{
    $report = new Report('0.1.0', '/tmp/test');
    $report->addFinding(new Finding(
        checkId: 'SS012',
        checkName: 'Debug Mode in Production',
        checkVersion: 1,
        severity: Severity::High,
        category: Category::Config,
        message: 'APP_DEBUG is set to true in .env.production',
        file: '.env.production',
        line: 3,
        symbol: 'APP_DEBUG',
        snippet: 'APP_DEBUG=true',
        remediation: 'Set APP_DEBUG=false',
    ));
    $report->finish();

    return $report;
}

it('renders console output', function () {
    $reporter = new ConsoleReporter;
    $output = $reporter->render(createTestReport());

    expect($output)->toContain('Stackshield Security Scan');
    expect($output)->toContain('SS012');
    expect($output)->toContain('APP_DEBUG');
    expect($output)->toContain('Grade:');
});

it('renders JSON output', function () {
    $reporter = new JsonReporter;
    $output = $reporter->render(createTestReport());
    $data = json_decode($output, true);

    expect($data)->toBeArray();
    expect($data['findings'])->toHaveCount(1);
    expect($data['findings'][0]['check_id'])->toBe('SS012');
    expect($data['grade'])->toBeString();
});

it('renders valid SARIF output', function () {
    $reporter = new SarifReporter;
    $output = $reporter->render(createTestReport());
    $data = json_decode($output, true);

    expect($data['version'])->toBe('2.1.0');
    expect($data['runs'])->toHaveCount(1);
    expect($data['runs'][0]['tool']['driver']['name'])->toBe('Stackshield Scanner');
    expect($data['runs'][0]['results'])->toHaveCount(1);
    expect($data['runs'][0]['results'][0]['ruleId'])->toBe('SS012');
    expect($data['runs'][0]['results'][0]['partialFingerprints'])->toHaveKey('stackshield/v1');
});

it('renders markdown output', function () {
    $reporter = new MarkdownReporter;
    $output = $reporter->render(createTestReport());

    expect($output)->toContain('# Stackshield Security Scan');
    expect($output)->toContain('SS012');
    expect($output)->toContain('**Grade:**');
});

it('renders empty report correctly', function () {
    $report = new Report('0.1.0', '/tmp/test');
    $report->finish();

    $consoleOutput = (new ConsoleReporter)->render($report);
    expect($consoleOutput)->toContain('No findings');

    $jsonOutput = (new JsonReporter)->render($report);
    $data = json_decode($jsonOutput, true);
    expect($data['total_findings'])->toBe(0);
    expect($data['grade'])->toBe('A');
});
