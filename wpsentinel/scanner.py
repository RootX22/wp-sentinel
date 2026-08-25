"""Orchestration: normalise the target, fingerprint, run every check.

Kept separate from the CLI so it can be driven as a library and tested without
going through argument parsing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import checks
from .fingerprint import Fingerprint, identify
from .http import Client
from .model import Finding, Severity, Target


@dataclass
class ScanResult:
    target: Target
    fingerprint: Fingerprint
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def worst(self) -> Severity:
        real = [f.severity for f in self.findings if f.severity > Severity.INFO]
        return max(real) if real else Severity.INFO

    def to_dict(self) -> dict:
        return {
            "target": self.target.base_url,
            "is_wordpress": self.fingerprint.is_wordpress,
            "version": self.fingerprint.version or None,
            "version_source": self.fingerprint.version_source or None,
            "checks_run": self.checks_run,
            "worst_severity": self.worst().label,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


def normalise_target(raw: str) -> Target:
    """Turn user input into a clean base URL, defaulting to https.

    A scheme-less "example.com" becomes https://example.com — defaulting to
    plaintext would be the wrong bias for a security tool.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError(f"could not parse a host from {raw!r}")
    base = f"{parsed.scheme}://{parsed.netloc}"
    # Preserve a path prefix for WordPress installed in a subdirectory.
    path = parsed.path.rstrip("/")
    if path and path != "/":
        base += path
    return Target(base_url=base, host=parsed.netloc)


def scan(client: Client, target: Target, *, only: set[str] | None = None) -> ScanResult:
    fp, fp_findings = identify(client, target.base_url)
    result = ScanResult(target=target, fingerprint=fp, findings=list(fp_findings))

    if not fp.is_wordpress:
        result.findings.append(Finding(
            check="not-wordpress",
            title="Target does not appear to run WordPress",
            severity=Severity.INFO,
            detail=("No WordPress markers were found. The remaining checks are "
                    "WordPress-specific and were skipped."),
            evidence=target.base_url,
        ))
        return result

    for check_id, fn in checks.ALL:
        if only and check_id not in only:
            continue
        result.checks_run.append(check_id)
        try:
            result.findings.extend(fn(client, target, fp))
        except Exception as exc:                       # noqa: BLE001
            # A crashing check costs that check, not the scan. This mirrors the
            # http layer's contract: one probe misbehaving must not lose the run.
            result.errors.append(f"{check_id}: {type(exc).__name__}: {exc}")

    # Worst first, then by check id for stable ordering across runs.
    result.findings.sort(key=lambda f: (-int(f.severity), f.check))
    return result
