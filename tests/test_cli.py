"""CLI-level tests: the authorisation gate, exit codes, and output shape."""

from __future__ import annotations

import json

from wpsentinel import cli

from .fake_wp import HARDENED, VULNERABLE, FakeWP


def test_authorisation_is_required(capsys):
    """The gate is the whole ethical posture of the tool; it must hold."""
    assert cli.main(["example.com"]) == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert "permission" in err.lower()


def test_authorisation_via_env(monkeypatch):
    monkeypatch.setenv("WP_SENTINEL_AUTHORISED", "1")
    # Nothing listening on this port: scan completes, target is "not wordpress",
    # so a clean exit. The point is that the gate did not block us.
    assert cli.main(["http://127.0.0.1:1", "--fail-on", "never"]) == cli.EXIT_OK


def test_missing_target_is_usage_error(capsys):
    assert cli.main([]) == cli.EXIT_USAGE


def test_unknown_check_id_is_usage_error(capsys):
    rc = cli.main(["example.com", "--i-have-permission", "--only", "nope"])
    assert rc == cli.EXIT_USAGE
    assert "unknown check" in capsys.readouterr().err.lower()


def test_list_checks_needs_no_authorisation(capsys):
    assert cli.main(["--list-checks"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "xmlrpc" in out and "wpconfig-backup" in out


def test_vulnerable_site_exits_with_findings(capsys):
    with FakeWP(VULNERABLE) as base:
        rc = cli.main([base, "--i-have-permission", "--fail-on", "medium"])
    assert rc == cli.EXIT_FINDINGS


def test_hardened_site_exits_clean(capsys):
    with FakeWP(HARDENED) as base:
        rc = cli.main([base, "--i-have-permission", "--fail-on", "medium"])
    assert rc == cli.EXIT_OK


def test_fail_on_critical_ignores_medium(capsys):
    """A site whose worst issue is MEDIUM must not trip --fail-on critical."""
    cfg = dict(HARDENED)
    cfg["xmlrpc"] = True          # xmlrpc is MEDIUM, nothing higher
    with FakeWP(cfg) as base:
        rc = cli.main([base, "--i-have-permission", "--fail-on", "critical"])
    assert rc == cli.EXIT_OK


def test_fail_on_never_is_always_zero(capsys):
    with FakeWP(VULNERABLE) as base:
        rc = cli.main([base, "--i-have-permission", "--fail-on", "never"])
    assert rc == cli.EXIT_OK


def test_json_output_is_valid_and_structured(capsys):
    with FakeWP(VULNERABLE) as base:
        cli.main([base, "--i-have-permission", "--json", "--fail-on", "never"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["is_wordpress"] is True
    assert payload["version"] == "6.4.2"
    assert payload["worst_severity"] == "critical"
    checks = {f["check"] for f in payload["findings"]}
    assert "wpconfig-backup" in checks
    for f in payload["findings"]:
        assert set(f) >= {"check", "title", "severity", "detail", "remediation"}


def test_text_output_is_not_coloured_when_piped(capsys):
    with FakeWP(VULNERABLE) as base:
        cli.main([base, "--i-have-permission", "--fail-on", "never"])
    assert "\033[" not in capsys.readouterr().out
