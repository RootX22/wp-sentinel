"""A small HTTP client wrapper.

Deliberately thin and built on urllib so the tool has no runtime dependencies —
it is the kind of thing you want to run from a locked-down box or a CI runner
without a pip install first.

The single most important property here is that `get` never raises for a
network- or server-side condition. A scanner that aborts the whole run because
one probe 500'd or timed out is useless against a real site, where some of the
probes are *expected* to fail (that a path 404s is often the good outcome). Every
failure comes back as a Response with `ok=False` and a reason.
"""

from __future__ import annotations

import gzip
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow 3xx: return the redirect response so its Location header
    is visible. urllib normally chases redirects, which turns an author-id
    disclosure (a 301 to /author/<login>/) into a 404 on the followed URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


DEFAULT_UA = "wp-sentinel/{version} (+https://github.com/RootX22/wp-sentinel)"
DEFAULT_TIMEOUT = 15.0
MAX_BODY_BYTES = 2_000_000     # 2 MB: enough for any HTML page, caps a hostile one


@dataclass
class Response:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    ok: bool = False
    error: str = ""

    def header(self, name: str) -> str:
        """Case-insensitive header lookup; '' when absent."""
        name = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name:
                return v
        return ""


class Client:
    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT, user_agent: str = "",
                 verify_tls: bool = True, version: str = "0"):
        self.timeout = timeout
        self.user_agent = user_agent or DEFAULT_UA.format(version=version)
        # verify_tls is exposed because internal WordPress installs behind a
        # corporate CA or a self-signed staging cert are a normal thing to scan.
        # It defaults to on; turning it off is the operator's explicit choice.
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        https = urllib.request.HTTPSHandler(context=ctx)
        # Two openers built once: the TLS context lives on the handler (an
        # OpenerDirector's .open() takes no context= argument), and the no-follow
        # variant swaps in a redirect handler that surfaces the 3xx instead of
        # chasing it — some checks need to read the Location header itself.
        self._opener = urllib.request.build_opener(https)
        self._opener_no_redirect = urllib.request.build_opener(https, _NoRedirect)

    def get(self, url: str, *, method: str = "GET", follow_redirects: bool = True) -> Response:
        req = urllib.request.Request(
            url, method=method,
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
        )
        opener = self._opener if follow_redirects else self._opener_no_redirect
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                return self._read(url, resp.status, resp, resp.headers)
        except urllib.error.HTTPError as exc:
            # A 4xx/5xx is a real, useful answer — a 403 on wp-config.php~ means
            # something different from a 404 — so it is a Response, not an error.
            body_holder = exc
            try:
                return self._read(url, exc.code, body_holder, exc.headers)
            except Exception:
                return Response(url=url, status=exc.code, ok=False, error=f"http {exc.code}")
        except (urllib.error.URLError, ssl.SSLError) as exc:
            return Response(url=url, ok=False, error=self._reason(exc))
        except (TimeoutError, socket.timeout):
            return Response(url=url, ok=False, error=f"timed out after {self.timeout:g}s")
        except (ConnectionError, OSError) as exc:
            return Response(url=url, ok=False, error=f"{type(exc).__name__}: {exc}")

    def head(self, url: str) -> Response:
        return self.get(url, method="HEAD")


    def _read(self, url, status, stream, raw_headers) -> Response:
        headers = {k: v for k, v in raw_headers.items()}
        raw = stream.read(MAX_BODY_BYTES)
        if (raw_headers.get("Content-Encoding") or "").lower() == "gzip":
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                pass
        # Bodies are decoded leniently: a scanner must cope with the mislabelled
        # and mis-encoded pages real servers return, not just clean UTF-8.
        charset = "utf-8"
        ctype = raw_headers.get("Content-Type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
        try:
            body = raw.decode(charset, errors="replace")
        except LookupError:
            body = raw.decode("utf-8", errors="replace")
        return Response(url=url, status=status, headers=headers, body=body,
                        ok=200 <= status < 300)

    @staticmethod
    def _reason(exc) -> str:
        reason = getattr(exc, "reason", exc)
        return str(reason)
