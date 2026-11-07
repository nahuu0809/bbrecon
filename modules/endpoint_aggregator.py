"""Endpoint aggregator — combines, deduplicates, and normalizes URLs from all sources."""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.banner import C


class EndpointAggregator:
    """Merges endpoints from crawler, JS analyzer, historical sources, and session."""

    def __init__(self, session):
        self.s = session
        self.endpoints: dict[str, dict] = {}  # normalized_url -> metadata
        self.parameterized: list[str] = []     # URLs with query params
        self.static: list[str] = []            # URLs without params

    def aggregate(self, crawler=None, js_analyzer=None, extra_urls: "list[str] | None" = None):
        """Collect endpoints from all sources, deduplicate, and classify."""
        print(C.section("ENDPOINT AGGREGATION"))

        # Collect from session (already has urls from gau, wayback, crawl, etc.)
        all_urls = list(self.s.urls)

        # Add crawler results
        if crawler:
            all_urls.extend(crawler.get_discovered_urls())

        # Add JS analyzer results
        if js_analyzer:
            base = self.s.target.rstrip("/")
            for ep in js_analyzer.get_endpoints():
                if ep.startswith("http"):
                    all_urls.append(ep)
                elif ep.startswith("/"):
                    all_urls.append(f"{base}{ep}")

        # Add extra URLs
        if extra_urls:
            all_urls.extend(extra_urls)

        print(C.info(f"Raw URLs collected: {len(all_urls)}"))

        # Normalize and deduplicate
        for url in all_urls:
            if not url or not url.startswith("http"):
                continue
            norm = self._normalize(url)
            if norm not in self.endpoints:
                self.endpoints[norm] = {
                    "original": url,
                    "params": list(parse_qs(urlparse(url).query).keys()),
                    "path": urlparse(url).path,
                    "host": urlparse(url).hostname or "",
                }

        # Classify
        for norm, meta in self.endpoints.items():
            if meta["params"]:
                self.parameterized.append(norm)
            else:
                self.static.append(norm)

        # Update session.urls with deduplicated set
        self.s.urls = list(self.endpoints.keys())

        # Summary
        print(C.ok(f"After deduplication: {len(self.endpoints)} unique endpoints"))
        print(C.ok(f"  With parameters  : {len(self.parameterized)}"))
        print(C.ok(f"  Static paths     : {len(self.static)}"))

        # Group by path pattern for fuzzing prioritization
        patterns = self._group_by_pattern()
        if patterns:
            print(C.info(f"  URL patterns     : {len(patterns)}"))

        return self.endpoints

    def _normalize(self, url: str) -> str:
        """Normalize URL: lowercase scheme/host, sort params, strip fragment."""
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path.rstrip("/") or "/"
            # Sort query params for consistent dedup
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(params.items()), doseq=True) if params else ""
            return urlunparse((scheme, netloc, path, "", sorted_query, ""))
        except Exception:
            return url

    def _group_by_pattern(self) -> dict[str, list[str]]:
        """Group URLs by path pattern (replace numeric IDs with {id})."""
        patterns: dict[str, list[str]] = {}
        for url in self.endpoints:
            path = urlparse(url).path
            # Replace numeric segments with {id}
            pattern = re.sub(r"/\d+(?=/|$)", "/{id}", path)
            patterns.setdefault(pattern, []).append(url)
        return {p: urls for p, urls in patterns.items() if len(urls) > 1}

    def get_parameterized_urls(self) -> list[str]:
        """URLs that have query parameters — priority targets for injection."""
        return self.parameterized

    def get_static_urls(self) -> list[str]:
        """URLs without params — targets for dir fuzzing."""
        return self.static

    def get_all_params(self) -> set[str]:
        """All unique parameter names across all endpoints."""
        params = set()
        for meta in self.endpoints.values():
            params.update(meta["params"])
        return params

    def get_urls_by_param(self, param_name: str) -> list[str]:
        """Get all URLs that use a specific parameter."""
        return [
            url for url, meta in self.endpoints.items()
            if param_name in meta["params"]
        ]
