"""Detect whether a target is WordPress, and pin its version.

Version detection deliberately consults several independent sources and takes
the most specific agreement, because any single one is easy to remove:

  * the `<meta name="generator">` tag           — often stripped by hardening
  * the RSS/Atom feed `<generator>` element      — stripped less often
  * `readme.html`                                 — removed by careful admins
  * versioned `?ver=` query strings on core assets — the hardest to hide, since
    they are added by WordPress itself to core CSS/JS and drive cache busting

Reporting *how* the version was learned matters: "found in an exposed
readme.html" is itself a finding, whereas "inferred from the feed generator" is
just detection. The caller gets both the version and its source.
"""

from __future__ import annotations

import re

from .http import Client
from .model import Finding, Severity

_META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([0-9.]+)?', re.I)
_FEED_GENERATOR = re.compile(
    r'<generator[^>]*>https?://wordpress\.org/\??v?=?\s*([0-9.]+)?', re.I)
_README_VERSION = re.compile(r'Version\s+([0-9.]+)', re.I)
_VER_QUERY = re.compile(r'[?&]ver=([0-9][0-9.]+)')

# Signals that identify WordPress even when the version is hidden.
_WP_MARKERS = (
    "/wp-content/", "/wp-includes/", "wp-json", "wp-emoji-release",
    'name="generator" content="WordPress',
)


class Fingerprint:
    def __init__(self, is_wordpress: bool, version: str = "",
                 version_source: str = "", markers: list[str] | None = None):
        self.is_wordpress = is_wordpress
        self.version = version
        self.version_source = version_source
        self.markers = markers or []


def _clean_version(v: str | None) -> str:
    if not v:
        return ""
    v = v.strip().rstrip(".")
    # A plausible WordPress version is major.minor(.patch); reject junk that the
    # loose regexes might scrape from an unrelated string.
    return v if re.fullmatch(r"\d+\.\d+(\.\d+)?", v) else ""


def identify(client: Client, base_url: str) -> tuple[Fingerprint, list[Finding]]:
    findings: list[Finding] = []
    markers: list[str] = []
    version = ""
    source = ""

    home = client.get(base_url + "/")

    if home.ok or home.body:
        for marker in _WP_MARKERS:
            if marker in home.body:
                markers.append(marker)
        if "x-powered-by" in {k.lower() for k in home.headers}:
            pass  # not WP-specific; left for the header check

        m = _META_GENERATOR.search(home.body)
        if m:
            markers.append("meta-generator")
            v = _clean_version(m.group(1))
            if v:
                version, source = v, "meta generator tag"

        # Core assets carry ?ver= matching the WordPress version. Take the
        # highest, since bundled libraries also carry their own ?ver.
        core_vers = [
            _clean_version(x) for x in _VER_QUERY.findall(home.body)
            if "/wp-includes/" in home.body
        ]
        core_vers = [v for v in core_vers if v]
        if core_vers and not version:
            version = max(core_vers, key=_version_key)
            source = "core asset ?ver query string"

    # Feed generator — a second opinion, stripped less often than the meta tag.
    if not version:
        feed = client.get(base_url + "/feed/")
        if feed.body:
            m = _FEED_GENERATOR.search(feed.body)
            if m:
                v = _clean_version(m.group(1))
                if v:
                    version, source = v, "RSS feed generator"
                    markers.append("feed-generator")

    # readme.html — its mere presence is a finding, not just a version source.
    readme = client.get(base_url + "/readme.html")
    if readme.ok and "wordpress" in readme.body.lower():
        markers.append("readme.html")
        findings.append(Finding(
            check="exposed-readme",
            title="Core readme.html is publicly readable",
            severity=Severity.LOW,
            detail=("WordPress ships readme.html, which states the exact core "
                    "version. Leaving it readable hands that to anyone."),
            evidence=readme.url,
            remediation="Delete readme.html, or deny it in the web server config.",
        ))
        if not version:
            m = _README_VERSION.search(readme.body)
            v = _clean_version(m.group(1) if m else "")
            if v:
                version, source = v, "exposed readme.html"

    is_wp = bool(markers)
    fp = Fingerprint(is_wp, version, source, markers)

    if is_wp:
        findings.insert(0, Finding(
            check="wordpress-detected",
            title=f"WordPress detected{f' (version {version})' if version else ''}",
            severity=Severity.INFO,
            detail=(f"Version {version} identified via {source}."
                    if version else
                    "Version could not be determined — core version disclosure "
                    "appears to be suppressed, which is good practice."),
            evidence=", ".join(sorted(set(markers))),
        ))

    return fp, findings


def _version_key(v: str) -> tuple:
    return tuple(int(p) for p in v.split("."))
