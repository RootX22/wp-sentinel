"""A configurable fake WordPress site for the test suite.

Serves canned responses for the paths the scanner probes, so the whole scan can
run end to end against a real socket without touching the internet or standing
up an actual WordPress install. Each vulnerability can be toggled, which is what
lets the tests assert both that a check fires when it should and stays silent
when it should not.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Default profile: a deliberately leaky site, so most checks have something to
# find. Individual tests copy this and turn features off.
VULNERABLE = {
    "wordpress": True,
    "version": "6.4.2",
    "readme": True,
    "wpconfig_backup": True,
    "debug_log": True,
    "dir_listing": True,
    "rest_users": True,
    "author_enum": True,
    "xmlrpc": True,
    "wp_cron": True,
    "registration": True,
    "security_headers": False,   # False => headers absent => finding
    "version_headers": True,
}

HARDENED = {
    "wordpress": True,
    "version": "",
    "readme": False,
    "wpconfig_backup": False,
    "debug_log": False,
    "dir_listing": False,
    "rest_users": False,
    "author_enum": False,
    "xmlrpc": False,
    "wp_cron": False,
    "registration": False,
    "security_headers": True,
    "version_headers": False,
}

NOT_WP = {**HARDENED, "wordpress": False}


def _home_html(cfg) -> str:
    if not cfg["wordpress"]:
        return "<html><body>Just a plain site.</body></html>"
    gen = (f'<meta name="generator" content="WordPress {cfg["version"]}">'
           if cfg["version"] else "")
    return (
        "<!doctype html><html><head>"
        f"{gen}"
        '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css'
        f'?ver={cfg["version"] or "6.4"}">'
        '</head><body><div class="wp-content">'
        '<img src="/wp-content/uploads/2024/logo.png">'
        "</body></html>"
    )


class Handler(BaseHTTPRequestHandler):
    cfg = VULNERABLE

    def log_message(self, *a):        # keep the test output clean
        pass

    def _send(self, code, body="", headers=None, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if self.cfg.get("security_headers"):
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if self.cfg.get("version_headers"):
            self.send_header("X-Powered-By", "PHP/8.1.2")
            self.send_header("Server", "Apache/2.4.52")
        else:
            self.send_header("Server", "nginx")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):      # noqa: N802,C901 — a router, necessarily branchy
        cfg = self.cfg
        path = self.path

        if path in ("/", ""):
            return self._send(200, _home_html(cfg))

        if path.startswith("/?author=1"):
            if cfg["author_enum"]:
                return self._send(301, "", {"Location": "/author/admin/"})
            return self._send(200, _home_html(cfg))

        if path == "/readme.html":
            if cfg["readme"]:
                return self._send(
                    200, f"<h1>WordPress</h1><p>Version {cfg['version'] or '6.4.2'}</p>")
            return self._send(404, "not found")

        if path == "/feed/":
            if cfg["wordpress"] and cfg["version"]:
                return self._send(
                    200,
                    f'<rss><channel><generator>https://wordpress.org/?v={cfg["version"]}'
                    "</generator></channel></rss>",
                    ctype="application/rss+xml")
            return self._send(200, "<rss><channel></channel></rss>")

        if path.startswith("/wp-config"):
            if cfg["wpconfig_backup"]:
                return self._send(
                    200,
                    "<?php\ndefine('DB_NAME', 'wp');\n"
                    "define('DB_PASSWORD', 'hunter2');\n"
                    "define('AUTH_KEY', 'x');\n$table_prefix = 'wp_';\n",
                    ctype="text/plain")
            return self._send(404, "not found")

        if path == "/wp-content/debug.log":
            if cfg["debug_log"]:
                return self._send(
                    200,
                    "[01-Jan-2024 00:00:00 UTC] PHP Notice: undefined index in "
                    "/var/www/html/wp-content/plugins/x/x.php on line 5\n",
                    ctype="text/plain")
            return self._send(404, "not found")

        if path in ("/wp-content/uploads/", "/wp-includes/", "/wp-content/plugins/"):
            if cfg["dir_listing"]:
                return self._send(
                    200, "<html><head><title>Index of /</title></head>"
                         "<body><h1>Index of /</h1></body></html>")
            return self._send(403, "forbidden")

        if path == "/wp-json/wp/v2/users":
            if cfg["rest_users"]:
                return self._send(
                    200, '[{"id":1,"name":"Admin","slug":"admin"}]',
                    ctype="application/json")
            return self._send(401, '{"code":"rest_cannot_access"}',
                              ctype="application/json")

        if path == "/xmlrpc.php":
            if cfg["xmlrpc"]:
                return self._send(405, "XML-RPC server accepts POST requests only.")
            return self._send(403, "forbidden")

        if path == "/wp-cron.php":
            if cfg["wp_cron"]:
                return self._send(200, "")
            return self._send(403, "forbidden")

        if path.startswith("/wp-login.php"):
            if "action=register" in path and cfg["registration"]:
                return self._send(
                    200, '<form><input name="user_login"><input name="user_email">'
                         "</form>")
            return self._send(200, '<form><input name="log"></form>')

        if path == "/wp-admin/install.php":
            return self._send(200, "<h1>Already Installed</h1>")

        return self._send(404, "not found")


class FakeWP:
    """Context manager yielding a base URL for the configured profile."""

    def __init__(self, cfg=None):
        self.cfg = dict(cfg or VULNERABLE)

    def __enter__(self):
        handler = type("H", (Handler,), {"cfg": self.cfg})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
