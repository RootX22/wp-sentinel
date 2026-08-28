# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-25

### Added
- Initial release: a detection-only WordPress security scanner. It observes and
  never exploits — every check requests a path a browser could request and
  judges the response; no login attempts, no payloads.
- Authorisation gate (`--i-have-permission` / `WP_SENTINEL_AUTHORISED=1`) that
  must be passed before any target is scanned.
- Fingerprinting: WordPress detection and core-version pinning from four
  independent sources (meta generator, feed generator, core asset `?ver=`
  strings, exposed `readme.html`), reporting how the version was learned.
- 12 checks across disclosure, endpoints, and headers:
  `wpconfig-backup`, `debug-log`, `install-script`, `directory-listing`,
  `wp-json-users`, `xmlrpc`, `author-enum`, `wp-cron`, `registration-open`,
  `exposed-readme`, `security-headers`, `version-headers`.
- Text and JSON output; `--fail-on` threshold exit codes for CI.
- No runtime dependencies; tested on Python 3.9–3.13, with CI scanning a real
  WordPress container end to end.

### Notes
- A check reporting a **false clean** — saying a site is fine when the issue it
  looks for is present — is treated as a security issue, not an ordinary bug.
  See `SECURITY.md`.

[1.0.0]: https://github.com/RootX22/wp-sentinel/releases/tag/v1.0.0
