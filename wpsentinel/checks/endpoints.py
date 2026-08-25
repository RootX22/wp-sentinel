"""Checks on WordPress endpoints that widen the attack surface when left open."""

from __future__ import annotations

from ..http import Client
from ..model import Finding, Severity, Target
from . import register


@register("xmlrpc")
def xmlrpc(client: Client, target: Target, fp) -> list[Finding]:
    """xmlrpc.php enables credential brute-force amplification and pingback DDoS.

    Detection only: a GET returns the "XML-RPC server accepts POST requests only"
    banner when it is enabled. The tool never sends a system.multicall or a
    login attempt — that would be the attack this warns about.
    """
    r = client.get(target.url("xmlrpc.php"))
    enabled = ("XML-RPC server accepts POST requests only" in r.body
               or (r.status == 405))
    if enabled:
        return [Finding(
            check="xmlrpc",
            title="XML-RPC interface is enabled",
            severity=Severity.MEDIUM,
            detail=("xmlrpc.php is reachable. system.multicall lets an attacker "
                    "test hundreds of passwords in one request, and pingback.ping "
                    "can be abused to make the site attack others."),
            evidence=r.url,
            remediation=("If nothing uses XML-RPC (Jetpack, the mobile app, some "
                         "remote publishers do), block xmlrpc.php at the web "
                         "server or via a filter."),
            references=["https://kinsta.com/blog/xmlrpc-php/"],
        )]
    return []


@register("wp-cron")
def wp_cron(client: Client, target: Target, fp) -> list[Finding]:
    """A publicly hittable wp-cron.php is a cheap request-amplification target."""
    r = client.get(target.url("wp-cron.php"))
    # wp-cron.php returns 200 with an empty body when reachable. A 404/403 means
    # it has been moved or blocked, which is the hardened state.
    if r.status == 200 and len(r.body) < 64:
        return [Finding(
            check="wp-cron",
            title="wp-cron.php is publicly reachable",
            severity=Severity.LOW,
            detail=("wp-cron.php can be triggered by anyone. Repeated hits force "
                    "expensive scheduled work and are a low-effort resource-"
                    "exhaustion vector."),
            evidence=r.url,
            remediation=("Set DISABLE_WP_CRON and drive cron from a real system "
                         "crontab, and block external access to wp-cron.php."),
        )]
    return []


@register("registration-open")
def registration(client: Client, target: Target, fp) -> list[Finding]:
    """Open registration on a site that does not need it grows the account base."""
    r = client.get(target.url("wp-login.php?action=register"))
    if not r.ok:
        return []
    # The register form is present only when registration is enabled; otherwise
    # WordPress redirects or shows "User registration is currently not allowed".
    if 'name="user_login"' in r.body and "not allowed" not in r.body.lower():
        return [Finding(
            check="registration-open",
            title="User self-registration is enabled",
            severity=Severity.LOW,
            detail=("Anyone can create an account. On a site that does not need "
                    "public accounts this is unnecessary attack surface and a "
                    "spam vector."),
            evidence=r.url,
            remediation=("Disable 'Anyone can register' in Settings → General "
                         "unless the site genuinely needs public accounts."),
        )]
    return []


@register("install-script")
def install_script(client: Client, target: Target, fp) -> list[Finding]:
    """wp-admin/install.php reachable can mean an unfinished or reset install."""
    r = client.get(target.url("wp-admin/install.php"))
    if r.ok and ("Already Installed" in r.body or "installation" in r.body.lower()):
        # "Already Installed" is the safe case; only a live installer is a finding.
        if "Already Installed" not in r.body and ("wp-config" in r.body.lower()
                                                  or 'name="weblog_title"' in r.body):
            return [Finding(
                check="install-script",
                title="WordPress installer is reachable",
                severity=Severity.HIGH,
                detail=("wp-admin/install.php is serving the installation form. On "
                        "a site with no database configured this can let an "
                        "attacker complete the install and take over."),
                evidence=r.url,
                remediation="Complete or remove the installation; block install.php.",
            )]
    return []
