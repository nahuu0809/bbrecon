"""HTTP probing module — checks if hosts respond and collects metadata."""
import concurrent.futures
import re
from core.banner import C
from core.session import Finding
from core import http_client


# Technology patterns detected from headers and body
HEADER_TECH_PATTERNS = {
    "Nginx":       [r"(?i)server:\s*nginx"],
    "Apache":      [r"(?i)server:\s*apache"],
    "IIS":         [r"(?i)server:\s*microsoft-iis"],
    "Cloudflare":  [r"(?i)cf-ray", r"(?i)server:\s*cloudflare"],
    "AWS":         [r"(?i)x-amz-", r"(?i)server:\s*amazons3"],
    "Express.js":  [r"(?i)x-powered-by:\s*express"],
    "PHP":         [r"(?i)x-powered-by:\s*php", r"(?i)set-cookie:.*PHPSESSID"],
    "ASP.NET":     [r"(?i)x-powered-by:\s*asp\.net", r"(?i)x-aspnet-version"],
    "Django":      [r"(?i)set-cookie:.*csrftoken"],
    "Laravel":     [r"(?i)set-cookie:.*laravel_session"],
    "Rails":       [r"(?i)set-cookie:.*_rails_session", r"(?i)x-request-id"],
}


class ProbeResult:
    """Result of probing a single host."""
    __slots__ = ("host", "url", "status", "title", "server", "technologies",
                 "content_length", "redirect_url", "elapsed", "alive")

    def __init__(self):
        self.host = ""
        self.url = ""
        self.status = 0
        self.title = ""
        self.server = ""
        self.technologies: list[str] = []
        self.content_length = 0
        self.redirect_url = ""
        self.elapsed = 0.0
        self.alive = False


class HttpProbe:
    """Probes hosts for HTTP/HTTPS availability and collects metadata."""

    def __init__(self, session):
        self.s = session
        self.results: list[ProbeResult] = []

    def probe_all(self, hosts: "list[str] | None" = None, workers: int = 20,
                  ports: "list[int] | None" = None):
        """Probe a list of hosts. Defaults to session subdomains + domain."""
        print(C.section("HTTP PROBING"))
        targets = hosts or ([self.s.domain] + list(self.s.subdomains))
        probe_ports = ports or [443, 80, 8080, 8443]

        # Build URL list
        urls_to_probe = []
        for host in targets:
            if host.startswith("http"):
                urls_to_probe.append(host)
            else:
                for port in probe_ports:
                    scheme = "https" if port in [443, 8443] else "http"
                    if port in [80, 443]:
                        urls_to_probe.append(f"{scheme}://{host}")
                    else:
                        urls_to_probe.append(f"{scheme}://{host}:{port}")

        print(C.info(f"Probing {len(urls_to_probe)} URLs across {len(targets)} hosts..."))

        # Probe in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(self._probe_url, urls_to_probe))

        # Keep only alive results, deduplicate per host (prefer HTTPS, lower port)
        alive = [r for r in results if r.alive]
        by_host: dict[str, ProbeResult] = {}
        for r in alive:
            existing = by_host.get(r.host)
            if existing is None:
                by_host[r.host] = r
            elif "https" in r.url and "https" not in existing.url:
                by_host[r.host] = r  # prefer HTTPS
            elif r.status == 200 and existing.status != 200:
                by_host[r.host] = r  # prefer 200

        self.results = list(by_host.values())

        # Update session
        for r in self.results:
            self.s.add_url(r.url)
            for tech in r.technologies:
                if tech not in self.s.technologies:
                    self.s.technologies.append(tech)

        # Display results
        print(C.ok(f"Alive: {len(self.results)} / {len(targets)} hosts"))
        for r in sorted(self.results, key=lambda x: x.status):
            tech_str = f" [{', '.join(r.technologies)}]" if r.technologies else ""
            title_str = f" — {r.title}" if r.title else ""
            print(f"  {C.DIM}{r.status}{C.RESET} {r.url}{title_str}{tech_str}")

        # Flag interesting responses
        self._flag_findings()

        return self.results

    def _probe_url(self, url: str) -> ProbeResult:
        """Probe a single URL."""
        result = ProbeResult()
        from urllib.parse import urlparse
        parsed = urlparse(url)
        result.host = parsed.hostname or ""
        result.url = url

        resp = http_client.get(url, timeout=6.0, follow_redirects=True)

        if resp.error or resp.status == 0:
            return result

        result.alive = True
        result.status = resp.status
        result.title = resp.title
        result.server = resp.server
        result.content_length = len(resp.body)
        result.elapsed = resp.elapsed
        if resp.url != url:
            result.redirect_url = resp.url

        # Detect technologies from headers
        header_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        for tech, patterns in HEADER_TECH_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, header_str):
                    result.technologies.append(tech)
                    break

        return result

    def _flag_findings(self):
        """Generate findings from probe results."""
        for r in self.results:
            # Interesting status codes
            if r.status in [401, 403]:
                self.s.add_finding(Finding(
                    title=f"Restricted endpoint ({r.status}): {r.url}",
                    severity="low",
                    description=f"Returns {r.status}. May be bypassable.",
                    url=r.url, module="probe.http"
                ))
            elif r.status >= 500:
                self.s.add_finding(Finding(
                    title=f"Server error ({r.status}): {r.url}",
                    severity="low",
                    description=f"Server returns {r.status}. May indicate misconfiguration.",
                    url=r.url, module="probe.http"
                ))

            # Version disclosure
            if r.server and re.search(r"\d+\.\d+", r.server):
                self.s.add_finding(Finding(
                    title=f"Server version disclosure: {r.server}",
                    severity="info",
                    description=f"Server header reveals version info: {r.server}",
                    url=r.url, module="probe.http"
                ))

    def get_alive_urls(self) -> list[str]:
        """Return URLs of alive hosts."""
        return [r.url for r in self.results if r.alive]
