"""Security-header hygiene on the WordPress home page.

These are low severity on their own — a missing header is a weakened defence,
not an open door — so they are reported as LOW/INFO and grouped, never inflated
into something that would drown out a readable wp-config backup.
"""

from __future__ import annotations

from ..http import Client
from ..model import Finding, Severity, Target
from . import register

# (header, severity, what its absence costs)
_EXPECTED = [
    ("Content-Security-Policy", Severity.LOW,
     "No CSP, so an injected script has nothing stopping it from running."),
    ("X-Frame-Options", Severity.LOW,
     "No framing protection, leaving the site open to clickjacking "
     "(unless a CSP frame-ancestors directive covers it)."),
    ("X-Content-Type-Options", Severity.LOW,
     "Missing nosniff, so browsers may MIME-sniff responses into executable types."),
    ("Strict-Transport-Security", Severity.LOW,
     "No HSTS, so a first request can be downgraded to plaintext HTTP."),
]


@register("security-headers")
def security_headers(client: Client, target: Target, fp) -> list[Finding]:
    r = client.get(target.url("/"))
    if not (r.ok or r.body):
        return []

    findings = []
    for name, sev, cost in _EXPECTED:
        if not r.header(name):
            # HSTS only makes sense over HTTPS; do not fault a plain-HTTP target
            # for lacking it — that is a different (reported) problem.
            if name == "Strict-Transport-Security" and not target.base_url.startswith("https"):
                continue
            findings.append(Finding(
                check="security-headers",
                title=f"Missing {name} header",
                severity=sev,
                detail=cost,
                evidence=f"{r.url} (response headers)",
                remediation=f"Send the {name} header from the web server or a plugin.",
            ))
    return findings


@register("version-headers")
def version_headers(client: Client, target: Target, fp) -> list[Finding]:
    """Server/X-Powered-By banners that volunteer exact software versions."""
    r = client.get(target.url("/"))
    findings = []
    for name in ("X-Powered-By", "Server"):
        val = r.header(name)
        # Only flag when a version number is actually present — "nginx" alone is
        # fine, "nginx/1.18.0" and "PHP/7.4.3" are the disclosure.
        if val and any(c.isdigit() for c in val) and "/" in val:
            findings.append(Finding(
                check="version-headers",
                title=f"{name} header discloses a software version",
                severity=Severity.INFO,
                detail=(f"The {name} header advertises '{val}'. Exact versions let "
                        "an attacker match known CVEs without probing."),
                evidence=f"{name}: {val}",
                remediation=(f"Suppress the version in {name} "
                             "(server_tokens off; expose_php Off)."),
            ))
    return findings
