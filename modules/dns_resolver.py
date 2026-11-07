"""DNS resolution module — verifies subdomains and maps IPs."""
import socket
import concurrent.futures
from core.banner import C
from core.session import Finding


class DNSResolver:
    """Resolves discovered subdomains to IP addresses."""

    def __init__(self, session):
        self.s = session
        # host -> [ip, ...]
        self.resolved: dict[str, list[str]] = {}
        # ip -> [host, ...]
        self.ip_map: dict[str, list[str]] = {}

    def resolve_all(self, hosts: "list[str] | None" = None, workers: int = 30):
        """Resolve a list of hosts. Defaults to session.subdomains + domain."""
        print(C.section("DNS RESOLUTION"))
        targets = hosts or ([self.s.domain] + list(self.s.subdomains))
        if not targets:
            print(C.warn("No hosts to resolve"))
            return

        print(C.info(f"Resolving {len(targets)} hosts ({workers} threads)..."))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(self._resolve_host, h): h for h in targets}
            for future in concurrent.futures.as_completed(future_map):
                host = future_map[future]
                try:
                    ips = future.result()
                    if ips:
                        self.resolved[host] = ips
                        for ip in ips:
                            self.ip_map.setdefault(ip, [])
                            if host not in self.ip_map[ip]:
                                self.ip_map[ip].append(host)
                except Exception:
                    pass

        # Store in session
        self.s.dns_records = self.resolved

        # Summary
        live = len(self.resolved)
        dead = len(targets) - live
        unique_ips = len(self.ip_map)
        print(C.ok(f"Resolved: {live} live, {dead} dead, {unique_ips} unique IPs"))

        # Flag shared hosting
        for ip, hosts_list in self.ip_map.items():
            if len(hosts_list) > 3:
                self.s.add_finding(Finding(
                    title=f"Shared IP: {ip} hosts {len(hosts_list)} subdomains",
                    severity="info",
                    description=f"IP {ip} resolves to: {', '.join(hosts_list[:10])}",
                    url="", module="dns.resolver"
                ))

        # Detect wildcard DNS
        self._detect_wildcard()

        return self.resolved

    def _resolve_host(self, host: str) -> list[str]:
        """Resolve a single hostname to IP addresses."""
        try:
            results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list(set(r[4][0] for r in results))
            if ips and self.s.verbose:
                print(f"  {C.DIM}{host} → {', '.join(ips)}{C.RESET}")
            return ips
        except (socket.gaierror, socket.herror, OSError):
            return []

    def _detect_wildcard(self):
        """Check if the domain has wildcard DNS by querying random subdomain."""
        import random
        import string
        random_sub = "".join(random.choices(string.ascii_lowercase, k=16))
        test_host = f"{random_sub}.{self.s.domain}"
        ips = self._resolve_host(test_host)
        if ips:
            self.s.add_finding(Finding(
                title="Wildcard DNS detected",
                severity="info",
                description=(
                    f"Random subdomain '{test_host}' resolves to {', '.join(ips)}. "
                    "Subdomain enumeration results may include false positives."
                ),
                url="", module="dns.resolver"
            ))
            print(C.warn(f"Wildcard DNS detected — {test_host} → {', '.join(ips)}"))

    def get_live_hosts(self) -> list[str]:
        """Return only subdomains that resolved successfully."""
        return list(self.resolved.keys())

    def get_ips_for_host(self, host: str) -> list[str]:
        return self.resolved.get(host, [])
