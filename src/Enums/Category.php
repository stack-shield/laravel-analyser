<?php

namespace StackShield\Analyser\Enums;

enum Category: string
{
    case Code = 'code';
    case Routes = 'routes';
    case Config = 'config';
    case Filesystem = 'filesystem';
    case Dependencies = 'dependencies';

    public function label(): string
    {
        return match ($this) {
            self::Code => 'Code',
            self::Routes => 'Routes',
            self::Config => 'Configuration',
            self::Filesystem => 'Filesystem',
            self::Dependencies => 'Dependencies',
        };
    }
}
