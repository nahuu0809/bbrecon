"""Parameter discovery — identifies hidden and injectable parameters."""
import concurrent.futures
from urllib.parse import urlparse, urlencode, parse_qs
from core.banner import C
from core.session import Finding
from core import http_client


# Known interesting parameter names by vulnerability class
INTERESTING_PARAMS = {
    "redirect": ["url", "redirect", "return", "next", "redir", "redirect_uri",
                  "return_url", "returnTo", "goto", "continue", "dest", "destination",
                  "redirect_to", "callback", "forward", "out", "view"],
    "file": ["file", "path", "filepath", "filename", "template", "page", "include",
             "dir", "document", "folder", "root", "pg", "style", "pdf", "img",
             "doc", "load"],
    "id": ["id", "user_id", "userId", "uid", "account_id", "accountId",
            "order_id", "orderId", "invoice_id", "record_id", "file_id",
            "doc_id", "document_id", "profile_id", "customer_id", "pid", "oid"],
    "search": ["q", "s", "search", "query", "keyword", "term", "find"],
    "ssrf": ["url", "uri", "link", "src", "source", "target", "dest", "host",
             "site", "fetch", "proxy", "domain", "callback", "ping", "feed",
             "webhook"],
}

# Common parameter names to brute-force
COMMON_PARAMS = [
    "id", "page", "file", "url", "search", "q", "lang", "token", "user",
    "email", "name", "sort", "order", "limit", "offset", "callback",
    "redirect", "next", "path", "template", "action", "type", "format",
    "debug", "test", "admin", "key", "api_key", "secret", "password",
    "auth", "session", "ref", "source", "target", "preview", "mode",
    "cmd", "exec", "command", "input", "output", "data", "value",
    "config", "settings", "category", "view", "status", "filter",
]


class ParamDiscovery:
    """Discovers hidden parameters by brute-forcing common names."""

    def __init__(self, session):
        self.s = session
        self.discovered: dict[str, list[str]] = {}  # url -> [param_names]
        self.interesting: list[dict] = []  # [{url, param, category}]

    def discover(self, urls: "list[str] | None" = None, workers: int = 5):
        """Discover hidden parameters on target URLs."""
        print(C.section("PARAMETER DISCOVERY"))

        targets = urls or [self.s.target]
        print(C.info(f"Testing {len(targets)} URLs for hidden parameters"))
        print(C.info(f"  Wordlist: {len(COMMON_PARAMS)} common parameter names"))

        for url in targets[:20]:  # limit to avoid excessive traffic
            found = self._brute_params(url, workers)
            if found:
                self.discovered[url] = found

        # Also classify already-known parameters
        self._classify_existing_params()

        # Summary
        total_params = sum(len(p) for p in self.discovered.values())
        print(C.ok(f"Discovered {total_params} hidden parameters across {len(self.discovered)} URLs"))
        if self.interesting:
            print(C.ok(f"  Interesting params: {len(self.interesting)}"))
            for item in self.interesting:
                self.s.add_finding(Finding(
                    title=f"Interesting parameter '{item['param']}' ({item['category']})",
                    severity="info",
                    description=f"Parameter '{item['param']}' found on {item['url']}. Category: {item['category']}.",
                    url=item["url"],
                    module="params.discovery"
                ))

        return self.discovered

    def _brute_params(self, url: str, workers: int) -> list[str]:
        """Brute-force parameter names on a URL by comparing response differences."""
        # Get baseline response
        baseline = http_client.get(url, timeout=6.0)
        if baseline.error or baseline.status == 0:
            return []

        baseline_len = len(baseline.body)
        baseline_status = baseline.status
        found = []

        def _test_param(param: str) -> "str | None":
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}=bbr3c0n_t3st"
            resp = http_client.get(test_url, timeout=6.0)
            if resp.error or resp.status == 0:
                return None

            # Heuristics: param is "accepted" if response changes meaningfully
            len_diff = abs(len(resp.body) - baseline_len)
            status_diff = resp.status != baseline_status

            # Significant body change or different status = param likely accepted
            if status_diff or (len_diff > 50 and len_diff / max(baseline_len, 1) > 0.02):
                return param
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = pool.map(_test_param, COMMON_PARAMS)
            for param in results:
                if param:
                    found.append(param)
                    if self.s.verbose:
                        print(f"  {C.DIM}{url} → param: {param}{C.RESET}")

        if found:
            print(C.ok(f"  {url}: {', '.join(found)}"))

        return found

    def _classify_existing_params(self):
        """Classify parameters already found in session URLs."""
        all_params = set()
        for url in self.s.urls:
            qs = parse_qs(urlparse(url).query)
            for param_name in qs:
                all_params.add((url, param_name))

        # Also include brute-forced params
        for url, params in self.discovered.items():
            for p in params:
                all_params.add((url, p))

        # Classify
        for url, param in all_params:
            for category, param_list in INTERESTING_PARAMS.items():
                if param.lower() in [p.lower() for p in param_list]:
                    self.interesting.append({
                        "url": url,
                        "param": param,
                        "category": category,
                    })
                    break

    def get_injectable_urls(self) -> list[dict]:
        """Return URLs + params categorized for specific vulnerability testing."""
        result = []
        for item in self.interesting:
            result.append({
                "url": item["url"],
                "param": item["param"],
                "vuln_type": item["category"],
            })
        return result
