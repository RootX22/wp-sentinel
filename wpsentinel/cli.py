"""Command-line interface, including the authorisation gate."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, checks
from .http import Client
from .model import Severity
from .scanner import normalise_target, scan

EXIT_OK = 0            # scan completed, nothing at or above the fail threshold
EXIT_FINDINGS = 1      # scan completed, findings at or above the threshold
EXIT_USAGE = 2         # bad arguments, or authorisation not given
EXIT_ERROR = 3         # the scan could not be completed

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"

AUTHORISATION_NOTICE = """\
wp-sentinel inspects a WordPress site for security misconfigurations. Run it
ONLY against sites you own or have explicit written permission to test.
Scanning systems without authorisation may be illegal.

Confirm authorisation with --i-have-permission (or set WP_SENTINEL_AUTHORISED=1).
"""


def _use_colour(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp-sentinel",
        description="Detection-only WordPress security scanner. Observes, never exploits.",
        epilog="Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage, 3 scan error.",
    )
    p.add_argument("target", nargs="?", help="site URL or hostname")
    p.add_argument("--i-have-permission", action="store_true",
                   help="assert you are authorised to scan this target")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--only", metavar="IDS",
                   help="comma-separated check ids to run (default: all)")
    p.add_argument("--list-checks", action="store_true",
                   help="list available check ids and exit")
    p.add_argument("-t", "--timeout", type=float, default=15.0,
                   help="per-request timeout in seconds (default: 15)")
    p.add_argument("--insecure", action="store_true",
                   help="do not verify the target's TLS certificate")
    p.add_argument("--fail-on", default="medium",
                   choices=["low", "medium", "high", "critical", "never"],
                   help="lowest severity that exits non-zero (default: medium)")
    p.add_argument("-V", "--version", action="version",
                   version=f"wp-sentinel {__version__}")
    return p


def _render_text(result, stream) -> None:
    colour = _use_colour(stream)

    def paint(sev: Severity, text: str) -> str:
        return f"{_COLOURS[sev]}{text}{_RESET}" if colour else text

    t = result.target
    print(f"\n  wp-sentinel — {t.base_url}", file=stream)
    if result.fingerprint.is_wordpress:
        v = result.fingerprint.version or "unknown"
        print(f"  WordPress: yes   version: {v}", file=stream)
    else:
        print("  WordPress: not detected", file=stream)
    print(file=stream)

    real = [f for f in result.findings if f.severity > Severity.INFO]
    info = [f for f in result.findings if f.severity == Severity.INFO]

    for f in real:
        tag = paint(f.severity, f"[{f.severity.label.upper():^8}]")
        print(f"  {tag} {f.title}", file=stream)
        print(f"           {f.detail}", file=stream)
        if f.evidence:
            print(f"           evidence:    {f.evidence}", file=stream)
        if f.remediation:
            print(f"           remediation: {f.remediation}", file=stream)
        print(file=stream)

    for f in info:
        print(f"  {paint(Severity.INFO, '[  INFO  ]')} {f.title}", file=stream)
    if info:
        print(file=stream)

    counts: dict[str, int] = {}
    for f in real:
        counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
    summary = "  ".join(f"{n} {s}" for s, n in counts.items()) or "no findings"
    print(f"  {len(real)} finding(s): {summary}", file=stream)
    if result.errors:
        print(f"  {len(result.errors)} check(s) errored: "
              f"{'; '.join(result.errors)}", file=stream)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        print("wordpress-detected  (always)")
        for check_id, _ in checks.ALL:
            print(check_id)
        return EXIT_OK

    if not args.target:
        print("wp-sentinel: a target is required", file=sys.stderr)
        return EXIT_USAGE

    authorised = args.i_have_permission or os.environ.get("WP_SENTINEL_AUTHORISED") == "1"
    if not authorised:
        print(AUTHORISATION_NOTICE, file=sys.stderr)
        return EXIT_USAGE

    try:
        target = normalise_target(args.target)
    except ValueError as exc:
        print(f"wp-sentinel: {exc}", file=sys.stderr)
        return EXIT_USAGE

    only = None
    if args.only:
        only = {c.strip() for c in args.only.split(",") if c.strip()}
        known = {cid for cid, _ in checks.ALL}
        unknown = only - known
        if unknown:
            print(f"wp-sentinel: unknown check id(s): {', '.join(sorted(unknown))}",
                  file=sys.stderr)
            return EXIT_USAGE

    client = Client(timeout=args.timeout, verify_tls=not args.insecure,
                    version=__version__)

    try:
        result = scan(client, target, only=only)
    except Exception as exc:                          # noqa: BLE001
        print(f"wp-sentinel: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        json.dump(result.to_dict(), sys.stdout, indent=2)
        print()
    else:
        _render_text(result, sys.stdout)

    if args.fail_on == "never":
        return EXIT_OK
    threshold = Severity.from_name(args.fail_on)
    if any(f.severity >= threshold for f in result.findings
           if f.severity > Severity.INFO):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
