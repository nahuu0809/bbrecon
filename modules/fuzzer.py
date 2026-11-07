"""Fuzzing engine — tests URL paths, parameters, headers, and JSON bodies."""
import re
import json
import concurrent.futures
from urllib.parse import urlparse, urlencode, quote
from core.banner import C
from core.session import Finding
from core import http_client


# ── Fuzz payloads organized by target ─────────────────────────────────────────

PATH_FUZZ_WORDLIST = [
    "admin", "api", "config", "debug", "backup", "test", "old", "dev",
    "staging", "internal", ".git", ".env", ".htaccess", "robots.txt",
    "sitemap.xml", "server-status", "server-info", "phpinfo.php",
    "wp-admin", "wp-login.php", "swagger", "swagger-ui", "graphql",
    "actuator", "actuator/health", "actuator/env", "console", "trace",
    "api/v1", "api/v2", "api/docs", "api/swagger.json",
    ".well-known/security.txt", "crossdomain.xml",
    "cgi-bin/", "wp-json/wp/v2/users",
    "web.config", "elmah.axd", "error_log", "access.log",
]

HEADER_FUZZ_PAYLOADS = {
    "X-Forwarded-For":  ["127.0.0.1", "localhost", "internal.target.com"],
    "X-Original-URL":   ["/admin", "/dashboard", "/internal"],
    "X-Rewrite-URL":    ["/admin", "/dashboard"],
    "X-Custom-IP-Authorization": ["127.0.0.1"],
    "X-Forwarded-Host": ["evil.com", "localhost"],
    "X-Host":           ["evil.com"],
    "Referer":          ["https://admin.internal/", "https://localhost/"],
}

PARAM_FUZZ_PAYLOADS = {
    "xss": [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "{{7*7}}",
    ],
    "sqli": [
        "'", "' OR '1'='1", "1' AND SLEEP(2)--", "' UNION SELECT NULL--",
    ],
    "lfi": [
        "../../etc/passwd", "..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    "ssrf": [
        "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
    ],
    "redirect": [
        "https://evil.com", "//evil.com",
    ],
    "rce": [
        "; id", "| id", "`id`", "$(id)", "%0aid",
    ],
}

# Detection patterns for each vuln type
DETECTION = {
    "xss": {
        "patterns": [r"<script>alert\(1\)</script>", r"onerror=alert\(1\)", r"49"],  # 7*7
        "severity": "high",
    },
    "sqli": {
        "patterns": [
            r"you have an error in your sql syntax",
            r"warning: mysql", r"unclosed quotation mark",
            r"syntax error.*postgresql", r"ORA-\d{5}",
            r"ODBC.*Driver", r"SQLite.*error",
        ],
        "severity": "critical",
    },
    "lfi": {
        "patterns": [r"root:.*:0:0:", r"\[fonts\]", r"PD9waHA"],
        "severity": "critical",
    },
    "ssrf": {
        "patterns": [r"root:.*:0:0:", r"ami-id", r"instance-id", r"redis_version"],
        "severity": "critical",
    },
    "redirect": {
        "patterns": [r"evil\.com"],
        "severity": "medium",
    },
    "rce": {
        "patterns": [r"uid=\d+.*gid=\d+", r"root:.*:0:0:"],
        "severity": "critical",
    },
}


class FuzzResult:
    __slots__ = ("url", "param", "payload", "vuln_type", "evidence", "status", "response_len")

    def __init__(self, url, param, payload, vuln_type, evidence, status, response_len):
        self.url = url
        self.param = param
        self.payload = payload
        self.vuln_type = vuln_type
        self.evidence = evidence
        self.status = status
        self.response_len = response_len


class Fuzzer:
    """Multi-mode fuzzer for paths, parameters, headers, and JSON bodies."""

    def __init__(self, session):
        self.s = session
        self.findings: list[FuzzResult] = []

    # ── Path fuzzing ──────────────────────────────────────────────────────────
    def fuzz_paths(self, base_url: str = "", wordlist: "list[str] | None" = None,
                   workers: int = 10):
        """Fuzz URL paths to discover hidden endpoints."""
        print(C.section("PATH FUZZING"))
        base = (base_url or self.s.target).rstrip("/")
        words = wordlist or PATH_FUZZ_WORDLIST
        print(C.info(f"Base: {base}, Wordlist: {len(words)} paths"))

        def _fuzz_path(word):
            url = f"{base}/{word}"
            resp = http_client.get(url, timeout=6.0)
            if resp.error:
                return None
            if resp.status in [200, 201, 204, 301, 302, 307, 401, 403]:
                return (url, resp.status, len(resp.body), resp.title)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_fuzz_path, words))

        found = [r for r in results if r]
        for url, status, size, title in found:
            self.s.add_url(url)
            severity = "info"
            if status in [200, 201] and any(kw in url.lower() for kw in
                    ["admin", ".git", ".env", "config", "backup", "debug",
                     "phpinfo", "actuator", "console", "swagger"]):
                severity = "medium"
            self.s.add_finding(Finding(
                title=f"Path discovered: {url} [{status}]",
                severity=severity,
                description=f"Status: {status}, Size: {size}, Title: {title}",
                url=url, module="fuzzer.path"
            ))

        print(C.ok(f"Path fuzzing found {len(found)} endpoints"))
        return found

    # ── Parameter fuzzing ─────────────────────────────────────────────────────
    def fuzz_params(self, url: str = "", vuln_types: "list[str] | None" = None,
                    workers: int = 5):
        """Fuzz query parameters with vulnerability-specific payloads."""
        print(C.section("PARAMETER FUZZING"))
        target = url or self.s.target
        types = vuln_types or list(PARAM_FUZZ_PAYLOADS.keys())
        print(C.info(f"Target: {target}"))
        print(C.info(f"Testing: {', '.join(types)}"))

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Get baseline
        baseline = http_client.get(target, timeout=6.0)
        baseline_body = baseline.body if not baseline.error else ""

        for vuln_type in types:
            payloads = PARAM_FUZZ_PAYLOADS.get(vuln_type, [])
            detection = DETECTION.get(vuln_type, {})
            patterns = detection.get("patterns", [])
            severity = detection.get("severity", "medium")

            for payload in payloads:
                # Inject into each existing param
                from urllib.parse import parse_qs
                params = parse_qs(parsed.query, keep_blank_values=True)
                if params:
                    for param_name in params:
                        test_params = dict(params)
                        test_params[param_name] = [payload]
                        test_url = f"{base}?{urlencode(test_params, doseq=True)}"
                        self._test_and_detect(test_url, param_name, payload,
                                              vuln_type, patterns, severity, baseline_body)
                else:
                    # No existing params — try injecting as ?test=PAYLOAD
                    test_url = f"{target}{'&' if '?' in target else '?'}test={quote(payload)}"
                    self._test_and_detect(test_url, "test", payload,
                                          vuln_type, patterns, severity, baseline_body)

        print(C.ok(f"Parameter fuzzing complete — {len(self.findings)} findings"))

    def _test_and_detect(self, test_url, param, payload, vuln_type, patterns,
                         severity, baseline_body):
        """Send request and check for vulnerability indicators."""
        resp = http_client.get(test_url, timeout=6.0)
        if resp.error or resp.status == 0:
            return

        body = resp.body
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                # Check it's not a false positive (was already in baseline)
                if re.search(pattern, baseline_body, re.IGNORECASE):
                    continue

                result = FuzzResult(
                    url=test_url, param=param, payload=payload,
                    vuln_type=vuln_type,
                    evidence=f"Pattern matched: {pattern}",
                    status=resp.status, response_len=len(body),
                )
                self.findings.append(result)

                self.s.add_finding(Finding(
                    title=f"[fuzzer] {vuln_type.upper()} via '{param}'",
                    severity=severity,
                    description=f"Payload: {payload}\nDetection: {pattern}",
                    url=test_url,
                    evidence=f"Param: {param}, Payload: {payload}",
                    module=f"fuzzer.params.{vuln_type}"
                ))
                return  # One match per payload is enough

    # ── Header fuzzing ────────────────────────────────────────────────────────
    def fuzz_headers(self, url: str = ""):
        """Fuzz HTTP headers for access control bypass and injection."""
        print(C.section("HEADER FUZZING"))
        target = url or self.s.target
        print(C.info(f"Target: {target}"))

        # Get baseline
        baseline = http_client.get(target, timeout=6.0)
        baseline_status = baseline.status if not baseline.error else 0
        baseline_len = len(baseline.body) if not baseline.error else 0

        for header_name, payloads in HEADER_FUZZ_PAYLOADS.items():
            for payload in payloads:
                resp = http_client.get(
                    target, headers={header_name: payload}, timeout=6.0
                )
                if resp.error:
                    continue

                # Detect access control bypass: 403 baseline → 200 with header
                if baseline_status == 403 and resp.status == 200:
                    self.s.add_finding(Finding(
                        title=f"Access bypass via {header_name}: {payload}",
                        severity="high",
                        description=(
                            f"Adding header '{header_name}: {payload}' changes "
                            f"response from {baseline_status} to {resp.status}."
                        ),
                        url=target,
                        evidence=f"Header: {header_name}: {payload}",
                        module="fuzzer.headers"
                    ))
                    break

                # Detect significant body change (possible SSRF/info leak)
                len_diff = abs(len(resp.body) - baseline_len)
                if len_diff > 200 and resp.status == 200:
                    self.s.add_finding(Finding(
                        title=f"Response change via header {header_name}",
                        severity="low",
                        description=(
                            f"Header '{header_name}: {payload}' causes significant "
                            f"response change ({len_diff} bytes difference)."
                        ),
                        url=target,
                        evidence=f"Header: {header_name}: {payload}, delta: {len_diff}",
                        module="fuzzer.headers"
                    ))

        print(C.ok("Header fuzzing complete"))

    # ── JSON body fuzzing ─────────────────────────────────────────────────────
    def fuzz_json(self, url: str = "", base_body: "dict | None" = None):
        """Fuzz JSON request bodies for injection vulnerabilities."""
        print(C.section("JSON BODY FUZZING"))
        target = url or self.s.target

        if base_body is None:
            print(C.warn("No base JSON body provided. Trying common structures..."))
            base_body = {"id": "1", "query": "test", "data": "value"}

        print(C.info(f"Target: {target}"))
        print(C.info(f"Base body keys: {list(base_body.keys())}"))

        for key in base_body:
            for vuln_type, payloads in PARAM_FUZZ_PAYLOADS.items():
                detection = DETECTION.get(vuln_type, {})
                patterns = detection.get("patterns", [])
                severity = detection.get("severity", "medium")

                for payload in payloads:
                    test_body = dict(base_body)
                    test_body[key] = payload
                    json_bytes = json.dumps(test_body).encode()

                    resp = http_client.request(
                        target, method="POST", data=json_bytes,
                        headers={"Content-Type": "application/json"},
                        timeout=6.0,
                    )
                    if resp.error:
                        continue

                    for pattern in patterns:
                        if re.search(pattern, resp.body, re.IGNORECASE):
                            self.s.add_finding(Finding(
                                title=f"[fuzzer] {vuln_type.upper()} in JSON body key '{key}'",
                                severity=severity,
                                description=f"JSON key: {key}\nPayload: {payload}\nDetection: {pattern}",
                                url=target,
                                evidence=f"Body: {json.dumps(test_body)}",
                                module=f"fuzzer.json.{vuln_type}"
                            ))
                            break  # one match per payload

        print(C.ok("JSON body fuzzing complete"))

    def get_findings(self) -> list[FuzzResult]:
        return self.findings
