"""Checks for information a WordPress site should not be handing out.

None of these exploit anything. They request paths a browser could request and
judge the response. That boundary — observe, never exploit — is deliberate and
is what keeps the tool usable against systems you are authorised to test without
crossing into attacking them.
"""

from __future__ import annotations

from ..http import Client
from ..model import Finding, Severity, Target
from . import register

# Backup and editor-litter names that routinely sit next to wp-config.php and,
# unlike wp-config.php itself, are served as plain text because the server only
# hands .php to the interpreter.
_WPCONFIG_LEFTOVERS = [
    "wp-config.php~", "wp-config.php.bak", "wp-config.php.save",
    "wp-config.php.old", "wp-config.php.orig", "wp-config.php.txt",
    "wp-config.php.swp", ".wp-config.php.swp", "wp-config.bak",
    "wp-config.php.1", "wp-config.old",
]


@register("wpconfig-backup")
def wpconfig_backups(client: Client, target: Target, fp) -> list[Finding]:
    """A readable wp-config backup leaks the database credentials and auth keys.

    This is about as bad as it gets for a WordPress site, hence CRITICAL when a
    body actually comes back containing config directives.
    """
    findings = []
    for name in _WPCONFIG_LEFTOVERS:
        r = client.get(target.url(name))
        if not r.ok:
            continue
        looks_like_config = ("DB_PASSWORD" in r.body or "DB_NAME" in r.body
                             or "table_prefix" in r.body or "AUTH_KEY" in r.body)
        if looks_like_config:
            findings.append(Finding(
                check="wpconfig-backup",
                title="Readable wp-config backup exposes database credentials",
                severity=Severity.CRITICAL,
                detail=("A backup copy of wp-config.php is served as plain text "
                        "and contains configuration directives. This exposes the "
                        "database credentials and secret auth keys."),
                evidence=r.url,
                remediation=("Delete every wp-config backup from the web root and "
                             "rotate the DB password and all salts in wp-config.php."),
            ))
            break   # one confirmed leak is the whole story; stop probing
    return findings


@register("debug-log")
def debug_log(client: Client, target: Target, fp) -> list[Finding]:
    """WP_DEBUG_LOG writes to wp-content/debug.log, world-readable by default."""
    r = client.get(target.url("wp-content/debug.log"))
    if r.ok and ("PHP" in r.body or "WordPress database error" in r.body
                 or "Stack trace" in r.body or "[" in r.body[:200]):
        return [Finding(
            check="debug-log",
            title="Debug log is publicly readable",
            severity=Severity.HIGH,
            detail=("wp-content/debug.log is readable. Debug logs routinely leak "
                    "absolute paths, SQL, and sometimes tokens embedded in "
                    "requests."),
            evidence=r.url,
            remediation=("Set WP_DEBUG_LOG to a path outside the web root, or deny "
                         "access to debug.log, and delete the current file."),
        )]
    return []


@register("directory-listing")
def directory_listing(client: Client, target: Target, fp) -> list[Finding]:
    """Autoindex on upload/plugin dirs reveals the full installed inventory."""
    findings = []
    for path in ("wp-content/uploads/", "wp-includes/", "wp-content/plugins/"):
        r = client.get(target.url(path))
        if r.ok and "Index of /" in r.body:
            findings.append(Finding(
                check="directory-listing",
                title=f"Directory listing enabled on /{path}",
                severity=Severity.MEDIUM,
                detail=("The web server returns an autoindex for this directory, "
                        "revealing files and the full set of installed plugins or "
                        "uploads."),
                evidence=r.url,
                remediation=("Disable autoindex (Options -Indexes on Apache; remove "
                             "autoindex on nginx)."),
            ))
    return findings


@register("wp-json-users")
def rest_user_enum(client: Client, target: Target, fp) -> list[Finding]:
    """The REST users endpoint lists login slugs unless it is locked down."""
    r = client.get(target.url("wp-json/wp/v2/users"))
    if not r.ok:
        return []
    # A JSON array of objects carrying "slug" is the login-name disclosure.
    if r.body.lstrip().startswith("[") and '"slug"' in r.body:
        slugs = _count(r.body, '"slug"')
        return [Finding(
            check="wp-json-users",
            title="REST API discloses user login names",
            severity=Severity.MEDIUM,
            detail=(f"/wp-json/wp/v2/users returns {slugs} user record(s) including "
                    "the 'slug', which is the account login name. This gives an "
                    "attacker half of every credential to brute-force."),
            evidence=r.url,
            remediation=("Restrict the users endpoint (many security plugins do "
                         "this), or filter rest_endpoints to remove it for "
                         "unauthenticated requests."),
        )]
    return []


@register("author-enum")
def author_enum(client: Client, target: Target, fp) -> list[Finding]:
    """?author=1 redirects to /author/<login>/, leaking the username."""
    r = client.get(target.url("?author=1"), follow_redirects=False)
    location = r.header("Location")
    hay = location or r.body
    if "/author/" in hay:
        seg = hay.split("/author/", 1)[1]
        login = seg.split("/", 1)[0].split("?", 1)[0]
        if login:
            return [Finding(
                check="author-enum",
                title="Author archives disclose user login names",
                severity=Severity.LOW,
                detail=("Requesting ?author=1 resolves to an author archive whose "
                        f"URL contains the login name ('{login}'). Iterating the "
                        "author id enumerates every user."),
                evidence=f"{r.url} -> .../author/{login}/",
                remediation=("Set a distinct nickname as the public display name, "
                             "and block ?author= enumeration at the edge."),
            )]
    return []


def _count(haystack: str, needle: str) -> int:
    return haystack.count(needle)
