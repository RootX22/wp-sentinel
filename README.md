# wp-sentinel

[![CI](https://github.com/RootX22/wp-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/RootX22/wp-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-0e75b6.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Dependencies: none](https://img.shields.io/badge/runtime%20deps-none-5ee1a0)

A **detection-only** WordPress security scanner. It finds the misconfigurations
that get WordPress sites compromised — a readable `wp-config` backup, an exposed
debug log, user-enumeration endpoints, an open XML-RPC — and tells you exactly
what to change.

It **observes, and never exploits.** Every check requests a path a browser could
request and judges the response. It sends no login attempts, no payloads, no
`system.multicall`. The line is deliberate: this is a tool for hardening sites
you are responsible for, not for attacking them.

```console
$ wp-sentinel example.com --i-have-permission

  wp-sentinel — https://example.com
  WordPress: yes   version: 6.4.2

  [CRITICAL] Readable wp-config backup exposes database credentials
           A backup copy of wp-config.php is served as plain text and contains
           configuration directives. This exposes the database credentials and
           secret auth keys.
           evidence:    https://example.com/wp-config.php~
           remediation: Delete every wp-config backup from the web root and
                        rotate the DB password and all salts in wp-config.php.

  [ MEDIUM ] REST API discloses user login names
           /wp-json/wp/v2/users returns 1 user record(s) including the 'slug',
           which is the account login name.
           remediation: Restrict the users endpoint, or filter rest_endpoints.

  14 finding(s): 1 critical  1 high  5 medium  7 low
$ echo $?
1
```

## Authorisation

Scanning a system you do not own or have written permission to test may be
illegal where you are. wp-sentinel will not run against a target until you
assert authorisation:

```bash
wp-sentinel example.com --i-have-permission
# or, for CI:
WP_SENTINEL_AUTHORISED=1 wp-sentinel example.com
```

This is a gate, not a licence. It is on you to actually have permission.

## Install

```bash
pip install git+https://github.com/RootX22/wp-sentinel.git
```

Or run it straight from a clone — there are **no runtime dependencies**, only the
Python standard library:

```bash
git clone https://github.com/RootX22/wp-sentinel.git
python3 -m wpsentinel example.com --i-have-permission
```

That is deliberate. A security tool you can drop onto a locked-down box and run
without a `pip install` is one you will actually run.

## What it checks

Detection is fingerprint-first: it confirms the target is WordPress and pins the
core version from several independent sources (meta generator, feed generator,
core asset `?ver=` strings, and `readme.html`), reporting *how* it learned the
version — because "found in an exposed readme.html" is itself a finding.

| Check | Severity | What it catches |
|---|---|---|
| `wpconfig-backup` | critical | `wp-config.php~`, `.bak`, `.save` etc. served as plain text, leaking DB credentials and auth keys |
| `debug-log` | high | Readable `wp-content/debug.log` leaking paths, SQL, tokens |
| `install-script` | high | A live `wp-admin/install.php` |
| `directory-listing` | medium | Autoindex on uploads / includes / plugins |
| `wp-json-users` | medium | REST endpoint disclosing login names |
| `xmlrpc` | medium | XML-RPC enabled (brute-force amplification, pingback abuse) |
| `author-enum` | low | `?author=1` leaking the login name |
| `wp-cron` | low | Publicly triggerable `wp-cron.php` |
| `registration-open` | low | Open self-registration |
| `exposed-readme` | low | `readme.html` disclosing the exact core version |
| `security-headers` | low | Missing CSP, X-Frame-Options, nosniff, HSTS |
| `version-headers` | info | `Server` / `X-Powered-By` advertising exact versions |

`wp-sentinel --list-checks` prints the current set.

## Usage

```bash
wp-sentinel example.com --i-have-permission          # full scan
wp-sentinel example.com --i-have-permission --json   # machine-readable
wp-sentinel example.com --i-have-permission --only xmlrpc,wp-json-users
wp-sentinel https://staging.internal --i-have-permission --insecure   # skip TLS verify
wp-sentinel example.com --i-have-permission --fail-on critical
```

| Flag | Default | Meaning |
|---|---|---|
| `--i-have-permission` | — | Required, unless `WP_SENTINEL_AUTHORISED=1` |
| `--json` | off | JSON to stdout |
| `--only IDS` | all | Comma-separated check ids |
| `--fail-on` | `medium` | `low` / `medium` / `high` / `critical` / `never` |
| `-t, --timeout` | `15` | Per-request timeout (seconds) |
| `--insecure` | off | Do not verify the target's TLS certificate |

**Exit codes:** `0` clean, `1` findings at or above `--fail-on`, `2` usage or
missing authorisation, `3` the scan could not run.

## In CI

Fail a pipeline when your own site regresses:

```yaml
- name: WordPress hardening check
  env:
    WP_SENTINEL_AUTHORISED: "1"    # this is our own site
  run: |
    pip install git+https://github.com/RootX22/wp-sentinel.git
    wp-sentinel https://our-site.example --fail-on high
```

## As a library

```python
from wpsentinel import scan
from wpsentinel.http import Client
from wpsentinel.scanner import normalise_target

result = scan(Client(version="1.0.0"), normalise_target("example.com"))
print(result.worst().label)
for f in result.findings:
    print(f.severity.label, f.check, f.evidence)
```

`scan()` never raises for a remote-side condition — a dead host, a timeout, a
crashing individual check all come back inside the result, because a scanner
that aborts on the first bad probe cannot scan a real site.

## What it is not

- **Not an exploitation tool.** No brute-forcing, no payloads, no proof-of-
  exploit. If you need that, you are past what this does on purpose.
- **Not a plugin CVE database.** It reports the core version and the installed
  surface it can see; it does not (yet) cross-reference plugin versions against
  a vulnerability feed. That is the natural next module — see the issues.
- **Not a WAF or a fix.** It tells you what is open. Closing it is still your job,
  and every finding says how.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

The suite runs every scan against a local fake WordPress server
(`tests/fake_wp.py`) with toggleable vulnerabilities, so each check is asserted
in **both** directions: it fires on a vulnerable profile and stays silent on a
hardened one. A scanner that only tests the positive case ships false positives,
which are worse than a missed finding — they teach the operator to ignore the
output.

## Licence

MIT
