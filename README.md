# Stackshield Scanner

A Laravel-aware static application security testing (SAST) tool. Scans your Laravel project for security vulnerabilities and misconfigurations.

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

Stackshield Scanner includes 40 security checks across 5 categories:

### Code Analysis
| ID | Check | Severity |
|----|-------|----------|
| SS001 | Mass Assignment (missing $fillable/$guarded) | High |
| SS002 | Raw SQL with tainted input | Critical |
| SS003 | Dangerous sinks (eval, shell_exec) with user input | Critical |
| SS007 | Unvalidated request input in controllers | Medium |
| SS008 | Hardcoded credentials in source code | High |
| SS009 | File upload without validation | High |
| SS040 | Insecure random number generation | Medium |
| SS041 | Open redirect via user input | High |
| SS042 | Weak hashing (md5/sha1 for passwords) | High |
| SS043 | Unsafe deserialization | Critical |
| SS044 | Blade raw output ({!! !!}) | Medium |
| SS053 | Missing authorization in controllers | Medium |
| SS054 | Mass delete without constraints | Medium |

### Configuration
| ID | Check | Severity |
|----|-------|----------|
| SS010 | APP_KEY missing, short, or committed | Critical |
| SS011 | Weak encryption cipher | Medium |
| SS012 | Debug mode enabled in production | High |
| SS013 | Dev tools (Telescope/Debugbar) in production | Medium |
| SS014 | Debug log level in production | Low |
| SS015 | Insecure session cookie settings | Medium |
| SS016 | Wildcard CORS configuration | Medium |
| SS017 | Mail driver set to log/array in production | Low |
| SS045 | Trusted proxies set to wildcard | Medium |
| SS046 | Broadcasting channels without auth | Medium |
| SS047 | Queue connection sync in production | Medium |
| SS048 | File cache driver in production | Low |
| SS049 | Missing HTTPS enforcement | Medium |

### Routes
| ID | Check | Severity |
|----|-------|----------|
| SS004 | Auth routes without rate limiting | Medium |
| SS005 | Route model binding without auth | Medium |
| SS006 | CSRF exemptions on state-changing routes | High |
| SS050 | API routes without rate limiting | Medium |
| SS051 | Debug/test routes in production | High |
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
| SS030 | Known security advisories | High |
| SS055 | Outdated Laravel version | Medium |
| SS056 | Known-insecure package versions | High |

## Grading

Reports include a letter grade based on findings:

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
php artisan stackshield:analyse-fix --check=SS001
```

Currently auto-fixable: SS001 (add $fillable), SS012 (disable debug mode).

## Requirements

- PHP 8.2+
- Laravel 10, 11, or 12

## License

MIT. See [LICENSE](LICENSE).
