"""Shared HTTP client with rate limiting, retries, and response parsing."""
import ssl
import urllib.request
import urllib.parse
import urllib.error
import urllib.response
import re
import time
from urllib.parse import urlparse
from core.rate_limiter import RateLimiter

# Reusable SSL context — verification disabled for self-signed certs on targets
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 BBRecon/2.0"

# Global rate limiter — modules can override per-session
_global_limiter = RateLimiter(requests_per_second=10.0, burst=5)


def get_limiter() -> RateLimiter:
    return _global_limiter


def set_limiter(limiter: RateLimiter) -> None:
    global _global_limiter
    _global_limiter = limiter


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return redirect responses as-is instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def _return_response(self, req, fp, code, msg, headers):
        return urllib.response.addinfourl(fp, headers, req.full_url, code=code)

    http_error_301 = _return_response
    http_error_302 = _return_response
    http_error_303 = _return_response
    http_error_307 = _return_response
    http_error_308 = _return_response


class HttpResponse:
    """Parsed HTTP response."""
    __slots__ = ("url", "status", "headers", "body", "elapsed", "error")

    def __init__(self, url: str, status: int, headers: dict, body: str,
                 elapsed: float, error: str = ""):
        self.url = url
        self.status = status
        self.headers = headers
        self.body = body
        self.elapsed = elapsed
        self.error = error

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def title(self) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", self.body, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else ""

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", self.headers.get("content-type", ""))

    @property
    def server(self) -> str:
        return self.headers.get("Server", self.headers.get("server", ""))

    def header(self, name: str) -> str:
        # Case-insensitive header lookup
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return ""


def _host_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or "default"


def _build_opener(follow_redirects: bool) -> urllib.request.OpenerDirector:
    handlers: list = [urllib.request.HTTPSHandler(context=_SSL_CTX)]
    if not follow_redirects:
        handlers.append(_NoRedirectHandler())
    return urllib.request.build_opener(*handlers)


def request(url: str, method: str = "GET", data: "dict | bytes | None" = None,
            headers: "dict | None" = None, timeout: float = 8.0,
            max_body: int = 200_000, follow_redirects: bool = True,
            rate_limit: bool = True) -> HttpResponse:
    """Make an HTTP request with rate limiting and error handling."""
    host = _host_from_url(url)

    if rate_limit:
        _global_limiter.wait(host)

    req_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }
    if headers:
        req_headers.update(headers)

    body_bytes = None
    if data is not None:
        if isinstance(data, dict):
            body_bytes = urllib.parse.urlencode(data).encode()
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, bytes):
            body_bytes = data

    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
    opener = _build_opener(follow_redirects)

    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(max_body)
            body = raw.decode("utf-8", errors="ignore")
            elapsed = time.monotonic() - t0
            return HttpResponse(
                url=getattr(resp, "url", resp.geturl()),
                status=getattr(resp, "status", resp.getcode()),
                headers=dict(resp.headers),
                body=body,
                elapsed=elapsed,
            )
    except urllib.error.HTTPError as e:
        elapsed = time.monotonic() - t0
        body = ""
        try:
            raw = e.read(max_body)
            body = raw.decode("utf-8", errors="ignore")
        except Exception:
            pass
        if e.code == 429:
            _global_limiter.notify_rate_limit(host)
        return HttpResponse(
            url=url, status=e.code, headers=dict(e.headers) if e.headers else {},
            body=body, elapsed=elapsed,
        )
    except Exception as e:
        elapsed = time.monotonic() - t0
        _global_limiter.notify_error(host)
        return HttpResponse(
            url=url, status=0, headers={}, body="",
            elapsed=elapsed, error=str(e),
        )


def get(url: str, **kwargs) -> HttpResponse:
    return request(url, method="GET", **kwargs)


def post(url: str, data: "dict | bytes | None" = None, **kwargs) -> HttpResponse:
    return request(url, method="POST", data=data, **kwargs)


def head(url: str, **kwargs) -> HttpResponse:
    kwargs.setdefault("max_body", 0)
    return request(url, method="HEAD", **kwargs)
