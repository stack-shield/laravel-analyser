<?php

namespace Stackshield\Scanner\Checks\Config;

use Stackshield\Scanner\Checks\Check;
use Stackshield\Scanner\Context;
use Stackshield\Scanner\Enums\Category;
use Stackshield\Scanner\Enums\Severity;
use Stackshield\Scanner\Finding;

class MailConfigCheck implements Check
{
    public function id(): string
    {
        return 'SS017';
    }

    public function name(): string
    {
        return 'Insecure Mail Configuration';
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function version(): int
    {
        return 1;
    }

    public function run(Context $ctx): iterable
    {
        foreach ($ctx->envFiles() as $envFile) {
            if ($envFile === '.env.example') {
                continue;
            }

            $env = $ctx->env($envFile);
            $appEnv = $env['APP_ENV'] ?? null;

            if ($envFile === '.env' && $appEnv !== 'production') {
                continue;
            }

            $mailer = $env['MAIL_MAILER'] ?? $env['MAIL_DRIVER'] ?? null;
            if ($mailer === 'log' || $mailer === 'array') {
                yield new Finding(
                    checkId: $this->id(),
                    checkName: $this->name(),
                    checkVersion: $this->version(),
                    severity: Severity::Low,
                    category: $this->category(),
                    message: "Mail driver is set to '{$mailer}' in {$envFile}. Emails won't be delivered in production.",
                    file: $envFile,
                    symbol: 'MAIL_MAILER',
                    remediation: "Configure a real mail driver (smtp, ses, mailgun, etc.) for production.",
                );
            }
        }
    }
}
