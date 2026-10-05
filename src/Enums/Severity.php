<?php

namespace StackShield\Analyser\Enums;

enum Severity: string
{
    case Info = 'info';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public function weight(): int
    {
        return match ($this) {
            self::Info => 0,
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Info => 'Info',
            self::Low => 'Low',
            self::Medium => 'Medium',
            self::High => 'High',
            self::Critical => 'Critical',
        };
    }

    public function color(): string
    {
        return match ($this) {
            self::Info => 'blue',
            self::Low => 'cyan',
            self::Medium => 'yellow',
            self::High => 'red',
            self::Critical => 'magenta',
        };
    }

    public function sarifLevel(): string
    {
        return match ($this) {
            self::Info => 'note',
            self::Low => 'note',
            self::Medium => 'warning',
            self::High => 'error',
            self::Critical => 'error',
        };
    }
}
