"""JavaScript endpoint analyzer — downloads and parses JS files for hidden routes."""
import re
import concurrent.futures
from urllib.parse import urljoin, urlparse
from core.banner import C
from core.session import Finding
from core import http_client


# Patterns that indicate API endpoints in JS source
ENDPOINT_PATTERNS = [
    # Absolute paths
    r'["\'](/api/[a-zA-Z0-9_/.-]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9_/.-]+)["\']',
    r'["\'](/graphql\b[^"\']*)["\']',
    r'["\'](/rest/[a-zA-Z0-9_/.-]+)["\']',
    r'["\'](/admin[a-zA-Z0-9_/.-]*)["\']',
    r'["\'](/internal[a-zA-Z0-9_/.-]*)["\']',

    # Relative paths that look like API routes
    r'(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*["\']([a-zA-Z0-9_/.-]+)["\']',
    r'(?:url|endpoint|path|route|href|action)\s*[=:]\s*["\'](/[a-zA-Z0-9_/.-]+)["\']',
    r'(?:baseURL|base_url|API_URL|API_BASE)\s*[=:+]\s*["\']([^"\']+)["\']',

    # Full URLs to external/internal APIs
    r'["\']https?://[a-zA-Z0-9._-]+(?::[0-9]+)?(/[a-zA-Z0-9_/.-]+)["\']',
]

# Patterns for secrets/credentials in JS
SECRET_PATTERNS = {
    "API Key":          r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
    "Bearer Token":     r'(?:bearer|authorization)\s*[=:]\s*["\']([a-zA-Z0-9_\-./+=]{20,})["\']',
    "AWS Key":          r'(AKIA[0-9A-Z]{16})',
    "Google Key":       r'(AIza[0-9A-Za-z_-]{35})',
    "Firebase URL":     r'(https?://[a-zA-Z0-9_-]+\.firebaseio\.com[^\s"\']*)',
    "S3 Bucket":        r'([a-zA-Z0-9_.-]+\.s3\.amazonaws\.com)',
    "JWT":              r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    "Private Key":      r'(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)',
    "Slack Token":      r'(xox[baprs]-[0-9a-zA-Z-]+)',
    "GitHub Token":     r'(ghp_[A-Za-z0-9_]{36})',
    "Stripe Key":       r'(sk_(?:live|test)_[A-Za-z0-9]{24,})',
    "Hardcoded Password": r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
}

# Parameters found in JS source
PARAM_PATTERNS = [
    r'(?:params|query|data)\s*[\[.]\s*["\']([a-zA-Z0-9_]+)["\']',
    r'(?:get|post)Param(?:eter)?\s*\(\s*["\']([a-zA-Z0-9_]+)["\']',
    r'name\s*[=:]\s*["\']([a-zA-Z0-9_]+)["\']',
    r'URLSearchParams.*?(?:get|set|append)\s*\(\s*["\']([a-zA-Z0-9_]+)["\']',
    r'(?:req\.(?:query|body|params))\s*\.\s*([a-zA-Z0-9_]+)',
]


class JSAnalyzer:
    """Downloads JS files and extracts API endpoints, secrets, and parameters."""

    def __init__(self, session):
        self.s = session
        self.endpoints: list[str] = []
        self.secrets: list[dict] = []
        self.params: set[str] = set()
        self.analyzed_count = 0

    def analyze(self, js_urls: "list[str] | None" = None, workers: int = 10):
        """Analyze a list of JS URLs. Discovers endpoints, secrets, params."""
        print(C.section("JAVASCRIPT ENDPOINT ANALYSIS"))

        urls = js_urls or []
        if not urls:
            print(C.warn("No JS files provided. Run the crawler first to discover JS files."))
            return

        # Deduplicate
        urls = list(set(urls))
        print(C.info(f"Analyzing {len(urls)} JavaScript files..."))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(self._analyze_single, urls))

        for endpoints, secrets, params in results:
            if endpoints or secrets or params:
                self.analyzed_count += 1
            self.endpoints.extend(endpoints)
            for secret in secrets:
                self.secrets.append(secret)
                self.s.add_finding(Finding(
                    title=f"Secret in JS: {secret['type']}",
                    severity="high" if secret["type"] != "Hardcoded Password" else "critical",
                    description=f"Found {secret['type']} in {secret['source']}",
                    url=secret["source"],
                    evidence=secret["value"][:100],
                    module="js.analyzer"
                ))
            self.params.update(params)

        # Deduplicate endpoints
        self.endpoints = list(set(self.endpoints))

        # Add discovered endpoints to session
        base = self.s.target.rstrip("/")
        for ep in self.endpoints:
            if ep.startswith("http"):
                self.s.add_url(ep)
            elif ep.startswith("/"):
                self.s.add_url(f"{base}{ep}")

        # Summary
        print(C.ok(f"Analyzed {self.analyzed_count} JS files with content"))
        print(C.ok(f"  Endpoints found  : {len(self.endpoints)}"))
        print(C.ok(f"  Secrets found    : {len(self.secrets)}"))
        print(C.ok(f"  Parameters found : {len(self.params)}"))

        # Flag interesting endpoints
        interesting = ["admin", "internal", "debug", "test", "staging",
                       "backup", "config", "secret", "private", "graphql"]
        for ep in self.endpoints:
            for kw in interesting:
                if kw in ep.lower():
                    self.s.add_finding(Finding(
                        title=f"Interesting JS endpoint: {ep}",
                        severity="medium" if kw in ["admin", "internal", "secret", "private"] else "info",
                        description=f"Endpoint with keyword '{kw}' found in JavaScript source.",
                        url=ep if ep.startswith("http") else f"{base}{ep}",
                        module="js.analyzer"
                    ))
                    break

        return self.endpoints

    def _analyze_single(self, url: str) -> "tuple[list[str], list[dict], set[str]]":
        """Download and analyze a single JS file."""
        endpoints = []
        secrets = []
        params: set[str] = set()

        resp = http_client.get(url, timeout=10.0, max_body=500_000)
        if resp.error or not resp.body:
            return endpoints, secrets, params

        source = resp.body

        # Extract endpoints
        for pattern in ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, source, re.IGNORECASE):
                ep = m.group(1)
                if len(ep) > 3 and not ep.endswith((".js", ".css", ".png", ".jpg")):
                    endpoints.append(ep)

        # Extract secrets
        for secret_type, pattern in SECRET_PATTERNS.items():
            for m in re.finditer(pattern, source, re.IGNORECASE):
                value = m.group(1)
                # Skip common false positives
                if len(value) < 8 or value in ("undefined", "null", "true", "false"):
                    continue
                if all(c == value[0] for c in value):  # repeated char
                    continue
                secrets.append({"type": secret_type, "value": value, "source": url})

        # Extract parameters
        for pattern in PARAM_PATTERNS:
            for m in re.finditer(pattern, source):
                param = m.group(1)
                if 2 < len(param) < 50:
                    params.add(param)

        return endpoints, secrets, params

    def get_endpoints(self) -> list[str]:
        return self.endpoints

    def get_params(self) -> set[str]:
        return self.params
