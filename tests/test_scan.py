"""End-to-end scans against the fake WordPress site.

The suite asserts both directions for every check: it fires on a vulnerable
profile, and it stays silent on a hardened one. A scanner that only tests the
positive case ships false positives, which are worse than a missed finding
because they train the operator to ignore the output.
"""

from __future__ import annotations

import pytest

from wpsentinel.http import Client
from wpsentinel.model import Severity
from wpsentinel.scanner import normalise_target, scan

from .fake_wp import HARDENED, NOT_WP, VULNERABLE, FakeWP


def run(cfg):
    with FakeWP(cfg) as base:
        client = Client(timeout=5, version="test")
        return scan(client, normalise_target(base))


def ids(result):
    return {f.check for f in result.findings}


# ── detection ───────────────────────────────────────────────────────────────

def test_detects_wordpress_and_version():
    r = run(VULNERABLE)
    assert r.fingerprint.is_wordpress
    assert r.fingerprint.version == "6.4.2"


def test_non_wordpress_target_skips_wp_checks():
    r = run(NOT_WP)
    assert not r.fingerprint.is_wordpress
    assert ids(r) == {"not-wordpress"}
    assert r.checks_run == []


def test_hardened_site_has_no_actionable_findings():
    """The whole false-positive question in one test.

    A locked-down site must come back clean apart from INFO context.
    """
    r = run(HARDENED)
    actionable = [f for f in r.findings if f.severity > Severity.INFO]
    assert actionable == [], f"false positives on a hardened site: {[f.check for f in actionable]}"


# ── individual checks, both directions ──────────────────────────────────────

@pytest.mark.parametrize("check_id", [
    "wpconfig-backup", "debug-log", "directory-listing", "wp-json-users",
    "author-enum", "xmlrpc", "wp-cron", "registration-open", "security-headers",
])
def test_check_fires_when_vulnerable(check_id):
    assert check_id in ids(run(VULNERABLE)), f"{check_id} did not fire on a vulnerable site"


@pytest.mark.parametrize("check_id", [
    "wpconfig-backup", "debug-log", "directory-listing", "wp-json-users",
    "author-enum", "xmlrpc", "wp-cron", "registration-open",
])
def test_check_silent_when_hardened(check_id):
    assert check_id not in ids(run(HARDENED)), f"{check_id} false-positived on a hardened site"


# ── severity and evidence ───────────────────────────────────────────────────

def test_wpconfig_backup_is_critical_with_evidence():
    r = run(VULNERABLE)
    f = next(f for f in r.findings if f.check == "wpconfig-backup")
    assert f.severity == Severity.CRITICAL
    assert f.evidence.startswith("http")          # points at the actual URL
    assert f.remediation                          # tells the operator what to do


def test_worst_severity_is_the_config_leak():
    r = run(VULNERABLE)
    assert r.worst() == Severity.CRITICAL


def test_findings_sorted_worst_first():
    r = run(VULNERABLE)
    real = [f for f in r.findings if f.severity > Severity.INFO]
    sevs = [int(f.severity) for f in real]
    assert sevs == sorted(sevs, reverse=True)


def test_author_enum_extracts_the_login_name():
    r = run(VULNERABLE)
    f = next(f for f in r.findings if f.check == "author-enum")
    assert "admin" in f.evidence


def test_rest_users_reports_the_count():
    r = run(VULNERABLE)
    f = next(f for f in r.findings if f.check == "wp-json-users")
    assert "1 user" in f.detail


# ── robustness ──────────────────────────────────────────────────────────────

def test_only_filter_runs_a_subset():
    with FakeWP(VULNERABLE) as base:
        client = Client(timeout=5, version="test")
        r = scan(client, normalise_target(base), only={"xmlrpc"})
    assert r.checks_run == ["xmlrpc"]
    # Fingerprinting is mandatory and emits its own findings (e.g. exposed-readme
    # is discovered while pinning the version), so --only constrains the check
    # phase, not detection. What it must guarantee: no *other* check ran.
    check_phase_ids = {"wpconfig-backup", "debug-log", "directory-listing",
                       "wp-json-users", "author-enum", "wp-cron",
                       "registration-open", "security-headers", "version-headers"}
    fired = {f.check for f in r.findings}
    assert not (fired & check_phase_ids), "a non-selected check ran"
    assert "xmlrpc" in fired


def test_scan_of_dead_host_does_not_raise():
    # Nothing listening: every probe fails, but scan() must return, not throw.
    client = Client(timeout=2, version="test")
    r = scan(client, normalise_target("http://127.0.0.1:1"))
    assert not r.fingerprint.is_wordpress
    assert "not-wordpress" in {f.check for f in r.findings}
