# StackShield Laravel Analyser

A Laravel-aware static application security testing (SAST) tool. Scans your Laravel project's source for security vulnerabilities and misconfigurations.

This is the static analyser behind StackShield's open source monitoring. For checks against a booted application at runtime, see [stackshield/scanner](https://github.com/stack-shield/scanner).

## Installation

```bash
composer require --dev stackshield/laravel-analyser
```

The service provider is auto-discovered by Laravel.

## Quick Start

```bash
# Run a scan
php artisan stackshield:analyse

# Output as JSON
php artisan stackshield:analyse --format=json

# Output as SARIF (for GitHub Code Scanning)
php artisan stackshield:analyse --format=sarif --output=results.sarif

# Fail CI on high+ severity findings
php artisan stackshield:analyse --fail-on=high

# List all available checks
php artisan stackshield:analyse-checks

# Auto-fix mechanical issues
php artisan stackshield:analyse-fix --dry-run
php artisan stackshield:analyse-fix
```

## Checks

The analyser includes 39 security checks across 5 categories. Checks marked *advisory* are heuristics static analysis cannot confirm (middleware applied elsewhere, validation in a form request): their findings are reported but do not count toward the grade.

### Code Analysis
| ID | Check | Severity |
|----|-------|----------|
| SS001 | Mass assignment: unvalidated request data reaching unguarded models, forceFill or forceCreate | High |
| SS002 | Raw SQL with tainted input | Critical |
| SS003 | Dangerous sinks (eval, shell_exec) with user input | Critical |
| SS007 | Unvalidated request input in controllers (advisory) | Medium |
| SS008 | Hardcoded credentials in source code | High |
| SS009 | Upload to a publicly served location without type validation | High |
| SS040 | Insecure random number generation | Medium |
| SS041 | Open redirect via user input | High |
| SS042 | Weak hashing (md5/sha1 for passwords) | High |
| SS043 | Unsafe deserialization | Critical |
| SS044 | Blade raw output ({!! !!}) of request data (named variables are advisory) | Medium |
| SS053 | Missing authorization in controllers (advisory) | Medium |
| SS054 | Unconstrained delete in an action reachable without auth | High |

### Configuration
| ID | Check | Severity |
|----|-------|----------|
| SS010 | APP_KEY missing, short, or committed | Critical |
| SS011 | Weak encryption cipher | Medium |
| SS012 | Debug mode enabled in production | High |
| SS013 | Debug tools (Debugbar, Ignition, dump server) in production require | Medium |
| SS014 | Debug log level in production | Low |
| SS015 | Insecure session cookie settings | Medium |
| SS016 | Wildcard CORS configuration | Medium |
| SS017 | Mail driver set to log/array in production | Low |
| SS045 | Trusted proxies hardcoded to wildcard | Medium |
| SS046 | Broadcasting channels without auth | Medium |
| SS047 | Queue connection sync in production | Medium |
| SS048 | File cache driver in production | Low |
| SS049 | Missing HTTPS enforcement (advisory) | Medium |

### Routes
| ID | Check | Severity |
|----|-------|----------|
| SS004 | Auth routes without rate limiting | Medium |
| SS005 | Route model binding without auth (advisory) | Medium |
| SS006 | CSRF exemptions covering session-authenticated, state-changing routes | High |
| SS050 | API routes without rate limiting | Medium |
| SS051 | Debug or phpinfo routes reachable without auth | High |
| SS052 | Overly broad wildcard routes | Low |

### Filesystem
| ID | Check | Severity |
|----|-------|----------|
| SS020 | Sensitive files in public web root | Critical |
| SS021 | Storage symlink misconfiguration | Medium |
| SS022 | World-writable sensitive files | High |
| SS057 | Writable config files | Medium |
| SS058 | Backup files in public directory | High |

### Dependencies
| ID | Check | Severity |
|----|-------|----------|
| SS030 | Known security advisories in composer.lock, one finding per package (Packagist advisory database; one network request, skipped with `offline: true`; advisories younger than `advisory_grace_days`, default 14, are reported but not graded) | From the advisory |
| SS055 | Laravel version past its security fixes | High |

## Grading

Reports include a letter grade based on graded (non-advisory) findings:

| Grade | Criteria |
|-------|----------|
| **A** | Zero high/critical findings, fewer than 3 medium |
| **B** | Zero critical, at most 1 high, fewer than 6 medium |
| **C** | At most 2 high findings |
| **D** | Everything else |

## Baseline

Suppress known findings so you can focus on new issues:

```bash
# Generate a baseline from current findings
php artisan stackshield:analyse-baseline

# Scan using the baseline (suppresses known findings)
php artisan stackshield:analyse --baseline=stackshield-baseline.yaml
```

When you bump a check's version, previously baselined findings for that check resurface.

## Configuration

Create a `stackshield.yaml` in your project root:

```yaml
checks:
  disabled:
    - SS014  # We intentionally use debug logging

  # Override severity for specific checks
  severity:
    SS048: medium

# Opt out of public OSS monitoring
monitoring:
  opt_out: true
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Console | `--format=console` | Human-readable terminal output (default) |
| JSON | `--format=json` | Machine-readable, CI integration |
| SARIF | `--format=sarif` | GitHub Code Scanning, IDE integration |
| Markdown | `--format=markdown` | PR comments, documentation |

## GitHub Action

Add to your workflow:

```yaml
- uses: stackshield/scan-action@v1
  with:
    php-version: '8.3'
    format: 'sarif'
    fail-on: 'high'
```

Or use the reusable workflow:

```yaml
jobs:
  security:
    uses: stackshield/laravel-analyser/.github/workflows/scan.yml@main
```

## Auto-Fix

Stackshield can automatically fix some mechanical issues:

```bash
# Preview fixes
php artisan stackshield:analyse-fix --dry-run

# Apply fixes
php artisan stackshield:analyse-fix

# Fix only a specific check
php artisan stackshield:analyse-fix --check=SS012
```

Currently auto-fixable: SS012 (disable debug mode).

## Requirements

- PHP 8.2+
- Laravel 10, 11, 12 or 13

## License

MIT. See [LICENSE](LICENSE).
