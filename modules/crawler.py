"""Web crawler — discovers endpoints by following internal links."""
import re
import time
import concurrent.futures
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque
from core.banner import C
from core.session import Finding
from core import http_client


class CrawlResult:
    """Aggregated crawl data for a single URL."""
    __slots__ = ("url", "status", "links", "forms", "params", "js_files")

    def __init__(self, url: str):
        self.url = url
        self.status = 0
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.params: list[str] = []
        self.js_files: list[str] = []


class Crawler:
    """BFS crawler that follows internal links and extracts endpoints."""

    def __init__(self, session, max_depth: int = 3, max_pages: int = 100,
                 delay: float = 0.0):
        self.s = session
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay
        self.visited: set[str] = set()
        self.results: list[CrawlResult] = []
        self.js_urls: set[str] = set()
        self.all_params: dict[str, set[str]] = {}  # url_path -> {param_names}
        self.forms_found: list[dict] = []

    def crawl(self, start_url: str = "", workers: int = 5):
        """BFS crawl starting from the given URL."""
        print(C.section("WEB CRAWLER"))
        seed = start_url or self.s.target
        if not seed.startswith("http"):
            seed = f"https://{seed}"

        base_domain = urlparse(seed).hostname or ""
        print(C.info(f"Crawling: {seed} (depth={self.max_depth}, max={self.max_pages})"))

        # BFS queue: (url, depth)
        queue: deque[tuple[str, int]] = deque()
        queue.append((seed, 0))
        self.visited.add(self._normalize(seed))

        pages_crawled = 0

        while queue and pages_crawled < self.max_pages:
            # Process batch
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < workers:
                batch.append(queue.popleft())

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self._fetch_page, url): (url, depth)
                           for url, depth in batch}
                for future in concurrent.futures.as_completed(futures):
                    url, depth = futures[future]
                    try:
                        cr = future.result()
                    except Exception:
                        continue

                    if cr is None:
                        continue

                    self.results.append(cr)
                    pages_crawled += 1
                    self.s.add_url(cr.url)

                    # Extract and store params
                    for param in cr.params:
                        path = urlparse(cr.url).path
                        self.all_params.setdefault(path, set()).add(param)

                    # Collect JS files
                    self.js_urls.update(cr.js_files)

                    # Collect forms
                    self.forms_found.extend(cr.forms)

                    # Enqueue discovered links (if within depth)
                    if depth < self.max_depth:
                        for link in cr.links:
                            norm = self._normalize(link)
                            link_host = urlparse(link).hostname or ""
                            if (norm not in self.visited
                                    and self._is_same_scope(link_host, base_domain)
                                    and not self._is_static_asset(link)):
                                self.visited.add(norm)
                                queue.append((link, depth + 1))

            if self.delay:
                time.sleep(self.delay)

        # Summary
        print(C.ok(f"Crawled {pages_crawled} pages"))
        print(C.ok(f"  Links discovered : {len(self.visited)}"))
        print(C.ok(f"  JS files found   : {len(self.js_urls)}"))
        print(C.ok(f"  Forms found      : {len(self.forms_found)}"))
        print(C.ok(f"  Unique params    : {sum(len(v) for v in self.all_params.values())}"))

        # Flag interesting forms
        for form in self.forms_found:
            if form.get("action", "").lower() in ["", "#"] or "file" in str(form.get("inputs", [])).lower():
                self.s.add_finding(Finding(
                    title=f"Form with file upload or self-action: {form.get('page', '')}",
                    severity="info",
                    description=f"Form action='{form.get('action')}', method='{form.get('method')}', inputs={form.get('inputs')}",
                    url=form.get("page", ""),
                    module="crawler"
                ))

        return self.results

    def _fetch_page(self, url: str) -> "CrawlResult | None":
        """Fetch a page and extract links, forms, JS files, params."""
        resp = http_client.get(url, timeout=8.0)
        if resp.error or resp.status == 0:
            return None

        cr = CrawlResult(url)
        cr.status = resp.status
        body = resp.body
        base = url

        # Extract links from <a href>
        for m in re.finditer(r'<a\s[^>]*href=["\']([^"\']+)["\']', body, re.IGNORECASE):
            href = m.group(1)
            full = urljoin(base, href)
            if full.startswith("http"):
                cr.links.append(full)
                # Extract params from link
                qs = parse_qs(urlparse(full).query)
                cr.params.extend(qs.keys())

        # Extract JS file references
        for m in re.finditer(r'<script\s[^>]*src=["\']([^"\']+)["\']', body, re.IGNORECASE):
            js = urljoin(base, m.group(1))
            if js.startswith("http"):
                cr.js_files.append(js)

        # Extract inline JS sources (import, fetch, axios)
        for m in re.finditer(r'(?:fetch|axios\.get|axios\.post|import)\s*\(\s*["\']([^"\']+)["\']', body):
            endpoint = m.group(1)
            if endpoint.startswith("/") or endpoint.startswith("http"):
                full = urljoin(base, endpoint)
                cr.links.append(full)

        # Extract forms
        for fm in re.finditer(r'<form\s[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL):
            form_html = fm.group(0)
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = urljoin(base, action_m.group(1)) if action_m else base
            method = (method_m.group(1) if method_m else "GET").upper()

            inputs = []
            for inp in re.finditer(r'<(?:input|textarea|select)\s[^>]*name=["\']([^"\']+)["\']', form_html, re.IGNORECASE):
                input_name = inp.group(1)
                inputs.append(input_name)
                cr.params.append(input_name)

            cr.forms.append({"page": url, "action": action, "method": method, "inputs": inputs})

        return cr

    def _normalize(self, url: str) -> str:
        """Normalize URL for dedup: strip fragment, trailing slash."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}?{parsed.query}" if parsed.query else f"{parsed.scheme}://{parsed.netloc}{path}"

    def _is_same_scope(self, host: str, base_domain: str) -> bool:
        """Check if host is within scope (same domain or subdomain)."""
        if not host:
            return False
        return host == base_domain or host.endswith(f".{base_domain}")

    def _is_static_asset(self, url: str) -> bool:
        """Skip images, fonts, CSS, etc."""
        path = urlparse(url).path.lower()
        skip_exts = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                     ".ttf", ".eot", ".mp3", ".mp4", ".avi", ".pdf", ".zip", ".gz"}
        return any(path.endswith(ext) for ext in skip_exts)

    def get_discovered_urls(self) -> list[str]:
        return list(self.visited)

    def get_js_urls(self) -> list[str]:
        return list(self.js_urls)

    def get_forms(self) -> list[dict]:
        return self.forms_found
