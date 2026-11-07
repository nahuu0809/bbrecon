"""Recon module: subdomains, ports, tech, headers."""
import socket
import re
import concurrent.futures
from core.banner import C
from core.session import Finding
from core import http_client


# Common subdomains to brute-force
COMMON_SUBS = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
    "app", "beta", "vpn", "cdn", "static", "assets", "media", "img",
    "portal", "dashboard", "login", "auth", "oauth", "sso", "blog",
    "shop", "store", "support", "help", "docs", "status", "monitor",
    "internal", "intranet", "corp", "cloud", "aws", "gcp", "azure",
    "s3", "git", "gitlab", "github", "jenkins", "ci", "jira", "confluence",
    "mx", "smtp", "pop", "imap", "ns1", "ns2", "dns", "proxy", "vpn2",
    "remote", "rdp", "ssh", "backup", "old", "legacy", "mobile", "m",
    "webmail", "cpanel", "whm", "plesk", "panel", "manage", "mgmt",
]

# Ports to scan (common web/infra)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    1433, 1521, 2222, 3000, 3306, 3389, 4443, 5000, 5432,
    5900, 6379, 7443, 8000, 8080, 8081, 8443, 8888, 9090,
    9200, 9443, 27017
]

# Technology fingerprints (header/body patterns)
TECH_SIGNATURES = {
    "WordPress":     [r"wp-content", r"wp-includes", r"WordPress"],
    "Drupal":        [r"Drupal", r"/sites/default/files"],
    "Joomla":        [r"Joomla", r"/components/com_"],
    "React":         [r"__REACT_DEVTOOLS", r"react-root", r'data-reactroot'],
    "Angular":       [r"ng-version", r"angular"],
    "Vue.js":        [r"__vue__", r"vue-router"],
    "Laravel":       [r"laravel_session", r"XSRF-TOKEN"],
    "Django":        [r"csrfmiddlewaretoken", r"djdt"],
    "Rails":         [r"_rails_session", r"X-Request-Id"],
    "Express.js":    [r"X-Powered-By: Express"],
    "PHP":           [r"X-Powered-By: PHP", r"PHPSESSID"],
    "ASP.NET":       [r"ASP.NET", r"__VIEWSTATE", r"X-AspNet-Version"],
    "Nginx":         [r"Server: nginx"],
    "Apache":        [r"Server: Apache"],
    "Cloudflare":    [r"cf-ray", r"cloudflare"],
    "AWS S3":        [r"AmazonS3", r"s3.amazonaws.com"],
    "GraphQL":       [r"graphql", r"__schema"],
    "Elasticsearch": [r"X-elastic-product"],
}

INTERESTING_HEADERS = {
    "X-Powered-By":              "info",
    "Server":                    "info",
    "X-Frame-Options":           "info",
    "Content-Security-Policy":   "info",
    "Strict-Transport-Security": "info",
    "X-Content-Type-Options":    "info",
    "Access-Control-Allow-Origin": "warn",
}


def _http_get(url, timeout=5):
    """Simple GET, returns (status, headers_dict, body_str) or None on error."""
    resp = http_client.get(url, timeout=timeout, max_body=50_000)
    if resp.error or resp.status == 0:
        return None
    return resp.status, resp.headers, resp.body


class ReconModule:
    def __init__(self, session):
        self.s = session

    # ──────────────────────────────────────────────
    # Subdomain enumeration
    # ──────────────────────────────────────────────
    def enumerate_subdomains(self):
        print(C.section("SUBDOMAIN ENUMERATION"))
        domain = self.s.domain
        found = []

        # 1. DNS brute-force
        print(C.info(f"DNS brute-force on {domain} ({len(COMMON_SUBS)} prefixes)..."))
        def _resolve(sub):
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except socket.gaierror:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            results = list(ex.map(_resolve, COMMON_SUBS))
        found += [r for r in results if r]

        # 2. crt.sh (certificate transparency)
        print(C.info("Querying crt.sh (certificate transparency)..."))
        ct_subs = self._crtsh(domain)
        for sub in ct_subs:
            if sub not in found:
                found.append(sub)

        for sub in sorted(set(found)):
            self.s.add_subdomain(sub)
            self.s.add_url(f"https://{sub}")

        print(C.ok(f"Found {len(self.s.subdomains)} subdomains"))

        # Check for interesting ones
        interesting = ["admin", "internal", "staging", "dev", "api", "jenkins", "gitlab"]
        for sub in self.s.subdomains:
            for kw in interesting:
                if kw in sub:
                    self.s.add_finding(Finding(
                        title=f"Interesting subdomain: {sub}",
                        severity="info",
                        description=f"Subdomain with sensitive keyword '{kw}' found",
                        url=f"https://{sub}",
                        module="recon.subdomains"
                    ))
                    break

    def _crtsh(self, domain):
        """Query crt.sh for known subdomains."""
        subs = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            result = _http_get(url, timeout=10)
            if result:
                import json
                data = json.loads(result[2])
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.splitlines():
                        line = line.strip().lstrip("*.")
                        if line.endswith(domain) and line not in subs:
                            subs.append(line)
        except Exception as e:
            self.s.warn(f"crt.sh query failed: {e}")
        return subs

    # ──────────────────────────────────────────────
    # Port scanning
    # ──────────────────────────────────────────────
    def port_scan(self):
        print(C.section("PORT SCAN"))
        targets = [self.s.domain] + self.s.subdomains[:5]  # limit for speed

        def _scan_port(host_port):
            host, port = host_port
            try:
                with socket.create_connection((host, port), timeout=1):
                    return (host, port)
            except Exception:
                return None

        for host in targets:
            print(C.info(f"Scanning {host}..."))
            pairs = [(host, p) for p in COMMON_PORTS]
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                results = list(ex.map(_scan_port, pairs))
            open_ports = [port for h, port in [r for r in results if r] if h == host]

            if open_ports:
                self.s.open_ports[host] = open_ports
                print(C.ok(f"{host}: open ports → {open_ports}"))

                # Interesting findings
                risky = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC"}
                for port in open_ports:
                    if port in risky:
                        self.s.add_finding(Finding(
                            title=f"Risky port open: {port}/{risky[port]}",
                            severity="medium",
                            description=f"{risky[port]} exposed on {host}:{port}",
                            url=f"{host}:{port}",
                            module="recon.ports"
                        ))
                    if port in [6379, 27017, 9200]:  # Redis, MongoDB, Elastic
                        svc = {6379:"Redis", 27017:"MongoDB", 9200:"Elasticsearch"}[port]
                        self.s.add_finding(Finding(
                            title=f"Database port exposed: {port}/{svc}",
                            severity="high",
                            description=f"{svc} port open on {host} — check if auth required",
                            url=f"{host}:{port}",
                            module="recon.ports"
                        ))

    # ──────────────────────────────────────────────
    # Technology detection
    # ──────────────────────────────────────────────
    def detect_technologies(self):
        print(C.section("TECHNOLOGY DETECTION"))
        url = self.s.target
        result = _http_get(url)
        if not result:
            self.s.err(f"Could not reach {url}")
            return

        status, headers, body = result
        combined = body + "\n".join(f"{k}: {v}" for k, v in headers.items())

        detected = []
        for tech, patterns in TECH_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, combined, re.IGNORECASE):
                    detected.append(tech)
                    break

        self.s.technologies = detected

        if detected:
            print(C.ok(f"Technologies detected: {', '.join(detected)}"))
            for tech in detected:
                self.s.add_finding(Finding(
                    title=f"Technology detected: {tech}",
                    severity="info",
                    description=f"{tech} identified via response fingerprinting",
                    url=url,
                    module="recon.tech"
                ))
        else:
            print(C.warn("No known technologies detected"))

    # ──────────────────────────────────────────────
    # HTTP header analysis
    # ──────────────────────────────────────────────
    def analyze_headers(self):
        print(C.section("HTTP HEADER ANALYSIS"))
        url = self.s.target
        result = _http_get(url)
        if not result:
            self.s.err(f"Could not reach {url}")
            return

        _, headers, _ = result
        headers_lower = {k.lower(): v for k, v in headers.items()}

        print(C.info("Response headers:"))
        for k, v in headers.items():
            print(f"  {C.DIM}{k}: {v}{C.RESET}")

        # Missing security headers
        security_headers = {
            "strict-transport-security": ("HSTS missing", "medium"),
            "content-security-policy":   ("CSP missing — XSS risk", "medium"),
            "x-frame-options":           ("Clickjacking protection missing", "low"),
            "x-content-type-options":    ("MIME sniffing protection missing", "low"),
            "referrer-policy":           ("Referrer policy missing", "low"),
            "permissions-policy":        ("Permissions policy missing", "low"),
        }

        for header, (desc, sev) in security_headers.items():
            if header not in headers_lower:
                self.s.add_finding(Finding(
                    title=desc,
                    severity=sev,
                    description=f"Header '{header}' not present in response from {url}",
                    url=url,
                    module="recon.headers"
                ))

        # CORS misconfiguration
        acao = headers_lower.get("access-control-allow-origin", "")
        if acao == "*":
            self.s.add_finding(Finding(
                title="Wildcard CORS policy",
                severity="medium",
                description="Access-Control-Allow-Origin: * allows any origin to read responses",
                url=url,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                module="recon.headers"
            ))

        # Info leakage via Server/X-Powered-By
        for h in ["server", "x-powered-by", "x-aspnet-version"]:
            if h in headers_lower:
                self.s.add_finding(Finding(
                    title=f"Version disclosure via {h}",
                    severity="info",
                    description=f"Server reveals: {headers_lower[h]}",
                    url=url,
                    module="recon.headers"
                ))

        print(C.ok("Header analysis complete"))
