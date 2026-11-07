"""Integration runner for external security tools."""
import subprocess
import shutil
import json
import os
import re
import ssl
import urllib.request
import urllib.parse
from pathlib import Path
from core.banner import C
from core.session import Finding


DEFAULT_WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


def _find_wordlist(custom=None):
    if custom and Path(custom).exists():
        return custom
    for path in DEFAULT_WORDLIST_PATHS:
        if Path(path).exists():
            return path
    return None


def _check_tool(name: str) -> bool:
    if shutil.which(name):
        return True
    print(C.warn(f"'{name}' not found in PATH. Install it first."))
    return False


def _run(cmd: list, cwd=None, timeout=300):
    """Run a subprocess and stream output line by line."""
    print(C.info(f"Running: {' '.join(cmd)}"))
    proc: "subprocess.Popen[str] | None" = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd,
        )
        lines = []
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                print(f"  {C.DIM}{line}{C.RESET}")
                lines.append(line)
        proc.wait(timeout=timeout)
        return proc.returncode, "\n".join(lines)
    except subprocess.TimeoutExpired:
        if proc is not None:
            proc.kill()
        print(C.err("Tool timed out"))
        return -1, ""
    except Exception as e:
        print(C.err(f"Error running tool: {e}"))
        return -1, ""


class IntegrationRunner:
    def __init__(self, session):
        self.s = session
        self.out = session.output_dir

    # ── nmap ──────────────────────────────────────────────────────────────────
    def run_nmap(self, target=None, flags=None):
        print(C.section("NMAP SCAN"))
        if not _check_tool("nmap"):
            return

        target = target or self.s.domain
        out_xml = str(self.out / "nmap_output")

        cmd = flags or [
            "nmap",
            "-sV",              # service/version detection
            "-sC",              # default scripts
            "--open",           # only show open ports
            "-T4",              # aggressive timing
            "-p", "21,22,23,25,53,80,110,143,443,445,993,995,"
                   "1433,1521,2222,3000,3306,3389,4443,5000,5432,"
                   "5900,6379,7443,8000,8080,8081,8443,8888,9090,"
                   "9200,9443,27017",
            "-oX", out_xml,     # XML output for parsing
            target,
        ]

        rc, output = _run(cmd)
        if rc == 0:
            print(C.ok(f"nmap complete. Output saved: {out_xml}.xml"))
            self._parse_nmap_xml(out_xml + ".xml")
        else:
            print(C.warn("nmap finished with non-zero exit code"))

    def _parse_nmap_xml(self, xml_path):
        """Parse nmap XML to extract open ports and add to session."""
        if not Path(xml_path).exists():
            return
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for host in root.findall("host"):
                addr_el = host.find("address")
                addr = addr_el.get("addr", "") if addr_el is not None else ""
                ports = host.find("ports")
                if not ports:
                    continue
                open_ports = []
                for port in ports.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        portid = int(port.get("portid", 0))
                        service = port.find("service")
                        svc_name = service.get("name", "") if service is not None else ""
                        svc_ver  = service.get("version", "") if service is not None else ""
                        open_ports.append(portid)
                        print(C.ok(f"  {addr}:{portid} — {svc_name} {svc_ver}"))
                if open_ports:
                    self.s.open_ports[addr] = open_ports
        except Exception as e:
            print(C.warn(f"Could not parse nmap XML: {e}"))

    # ── ffuf ──────────────────────────────────────────────────────────────────
    def run_ffuf(self, target=None, wordlist=None, extensions=None):
        print(C.section("FFUF DIRECTORY BRUTEFORCE"))
        if not _check_tool("ffuf"):
            print(C.info("Install: go install github.com/ffuf/ffuf/v2@latest"))
            return

        target = target or self.s.target
        if not target.endswith("/"):
            target += "/"

        wl = _find_wordlist(wordlist)
        if not wl:
            print(C.err("No wordlist found. Specify with --wordlist or install seclists/dirb"))
            return

        out_json = str(self.out / "ffuf_output.json")
        ext = extensions or "php,html,js,txt,json,bak,old,zip"

        cmd = [
            "ffuf",
            "-u", f"{target}FUZZ",
            "-w", wl,
            "-e", ext,
            "-mc", "200,201,204,301,302,307,401,403,405",  # match these status codes
            "-o", out_json,
            "-of", "json",
            "-t", "40",         # threads
            "-timeout", "5",
            "-c",               # colorize
            "-ac",              # auto-calibrate (filter false positives)
        ]

        rc, output = _run(cmd)
        print(C.ok(f"ffuf complete. Results saved: {out_json}"))
        self._parse_ffuf_json(out_json)

    def _parse_ffuf_json(self, json_path):
        if not Path(json_path).exists():
            return
        try:
            data = json.loads(Path(json_path).read_text())
            results = data.get("results", [])
            print(C.ok(f"ffuf found {len(results)} URLs"))
            for r in results:
                url = r.get("url", "")
                status = r.get("status", 0)
                self.s.add_url(url)
                # Flag interesting paths
                interesting_kw = ["admin", "backup", ".git", "config", "debug",
                                   "test", "api", "swagger", "upload", "env", ".env"]
                for kw in interesting_kw:
                    if kw in url.lower():
                        self.s.add_finding(Finding(
                            title=f"Interesting path discovered: {url}",
                            severity="medium" if kw in [".git", ".env", "backup"] else "low",
                            description=f"Path '{url}' (HTTP {status}) contains keyword '{kw}'",
                            url=url,
                            module="integrations.ffuf"
                        ))
                        break
        except Exception as e:
            print(C.warn(f"Could not parse ffuf output: {e}"))

    # ── nuclei ────────────────────────────────────────────────────────────────
    def run_nuclei(self, target=None, templates=None, severity=None):
        print(C.section("NUCLEI TEMPLATE SCAN"))
        if not _check_tool("nuclei"):
            print(C.info("Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"))
            return

        target = target or self.s.target
        out_json = str(self.out / "nuclei_output.json")

        cmd = [
            "nuclei",
            "-u", target,
            "-o", out_json,
            "-json-export", out_json,
            "-silent",
            "-stats",
        ]

        if templates:
            cmd += ["-t", templates]
        else:
            # Default: use tags covering common web vulns
            cmd += ["-tags", "cve,misconfig,exposure,xss,sqli,ssrf,lfi,rce,idor"]

        if severity:
            cmd += ["-severity", severity]
        else:
            cmd += ["-severity", "info,low,medium,high,critical"]

        rc, output = _run(cmd, timeout=600)
        print(C.ok(f"nuclei complete. Results saved: {out_json}"))
        self._parse_nuclei_json(out_json)

    def _parse_nuclei_json(self, json_path):
        if not Path(json_path).exists():
            return
        try:
            lines = Path(json_path).read_text().strip().splitlines()
            for line in lines:
                if not line.strip():
                    continue
                r = json.loads(line)
                sev_map = {
                    "critical": "critical",
                    "high":     "high",
                    "medium":   "medium",
                    "low":      "low",
                    "info":     "info",
                }
                sev = sev_map.get(r.get("info", {}).get("severity", "info"), "info")
                self.s.add_finding(Finding(
                    title=f"[nuclei] {r.get('info', {}).get('name', 'Finding')}",
                    severity=sev,
                    description=r.get("info", {}).get("description", ""),
                    url=r.get("matched-at", ""),
                    evidence=str(r.get("extracted-results", "")),
                    module="integrations.nuclei"
                ))
            print(C.ok(f"Parsed {len(lines)} nuclei findings"))
        except Exception as e:
            print(C.warn(f"Could not parse nuclei output: {e}"))

    # ── amass ─────────────────────────────────────────────────────────────────
    def run_amass(self, passive=True):
        print(C.section("AMASS SUBDOMAIN ENUMERATION"))
        if not _check_tool("amass"):
            print(C.info("Install: go install -v github.com/owasp-amass/amass/v4/...@master"))
            return

        out_txt = str(self.out / "amass_output.txt")
        cmd = ["amass", "enum", "-d", self.s.domain, "-o", out_txt]
        if passive:
            cmd.append("-passive")

        _run(cmd, timeout=600)
        if Path(out_txt).exists():
            subs = [l.strip() for l in Path(out_txt).read_text().splitlines() if l.strip()]
            for sub in subs:
                self.s.add_subdomain(sub)
            print(C.ok(f"amass found {len(subs)} subdomains"))

    # ── subfinder ─────────────────────────────────────────────────────────────
    def run_subfinder(self):
        print(C.section("SUBFINDER SUBDOMAIN ENUMERATION"))
        if not _check_tool("subfinder"):
            print(C.info("Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"))
            return

        out_txt = str(self.out / "subfinder_output.txt")
        cmd = ["subfinder", "-d", self.s.domain, "-o", out_txt, "-silent"]
        _run(cmd, timeout=300)
        if Path(out_txt).exists():
            subs = [l.strip() for l in Path(out_txt).read_text().splitlines() if l.strip()]
            for sub in subs:
                self.s.add_subdomain(sub)
            print(C.ok(f"subfinder found {len(subs)} subdomains"))

    # ── massdns ───────────────────────────────────────────────────────────────
    def run_massdns(self, wordlist=None, resolvers=None):
        print(C.section("MASSDNS BULK DNS RESOLUTION"))
        if not _check_tool("massdns"):
            print(C.info("Install: https://github.com/blechschmidt/massdns"))
            return

        wl = _find_wordlist(wordlist)
        if not wl:
            print(C.err("No wordlist found. Specify with --wordlist"))
            return

        # Build subdomain input list from wordlist + domain
        sublist_path = str(self.out / "massdns_input.txt")
        domain = self.s.domain
        with open(sublist_path, "w") as f:
            for line in Path(wl).read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    f.write(f"{line}.{domain}\n")

        default_resolvers = "/usr/share/massdns/lists/resolvers.txt"
        resolvers_path = resolvers or (default_resolvers if Path(default_resolvers).exists() else None)
        if not resolvers_path:
            print(C.warn("No resolvers file found. Use --resolvers to specify one."))
            return

        out_txt = str(self.out / "massdns_output.txt")
        cmd = ["massdns", "-r", resolvers_path, "-t", "A", "-o", "S", "-w", out_txt, sublist_path]
        _run(cmd, timeout=600)

        if Path(out_txt).exists():
            subs = []
            for line in Path(out_txt).read_text().splitlines():
                # Format: subdomain.domain.com. A 1.2.3.4
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "A":
                    sub = parts[0].rstrip(".")
                    subs.append(sub)
                    self.s.add_subdomain(sub)
            print(C.ok(f"massdns resolved {len(subs)} subdomains"))

    # ── masscan ───────────────────────────────────────────────────────────────
    def run_masscan(self, target=None, ports="0-65535", rate=10000):
        print(C.section("MASSCAN FAST PORT SCAN"))
        if not _check_tool("masscan"):
            print(C.info("Install: apt install masscan"))
            return

        target = target or self.s.domain
        out_json = str(self.out / "masscan_output.json")
        cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oJ", out_json]
        _run(cmd, timeout=600)
        if Path(out_json).exists():
            self._parse_masscan_json(out_json)

    def _parse_masscan_json(self, json_path):
        try:
            data = json.loads(Path(json_path).read_text())
            for entry in data:
                ip = entry.get("ip", "")
                for port_info in entry.get("ports", []):
                    port = port_info.get("port", 0)
                    self.s.open_ports.setdefault(ip, [])
                    if port not in self.s.open_ports[ip]:
                        self.s.open_ports[ip].append(port)
                        print(C.ok(f"  {ip}:{port} open"))
            total = sum(len(v) for v in self.s.open_ports.values())
            print(C.ok(f"masscan found {total} open ports"))
        except Exception as e:
            print(C.warn(f"Could not parse masscan output: {e}"))

    # ── httpx ─────────────────────────────────────────────────────────────────
    def run_httpx(self, targets=None):
        print(C.section("HTTPX HTTP PROBING"))
        if not _check_tool("httpx"):
            print(C.info("Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"))
            return

        target_list = targets or self.s.subdomains or [self.s.domain]
        targets_file = str(self.out / "httpx_input.txt")
        Path(targets_file).write_text("\n".join(target_list))

        out_json = str(self.out / "httpx_output.json")
        cmd = [
            "httpx", "-l", targets_file, "-json", "-o", out_json,
            "-title", "-status-code", "-tech-detect", "-follow-redirects", "-silent",
        ]
        _run(cmd, timeout=300)
        if Path(out_json).exists():
            self._parse_httpx_json(out_json)

    def _parse_httpx_json(self, json_path):
        try:
            lines = [l for l in Path(json_path).read_text().strip().splitlines() if l.strip()]
            for line in lines:
                r = json.loads(line)
                url = r.get("url", "")
                status = r.get("status-code", 0)
                if url:
                    self.s.add_url(url)
                for tech in r.get("technologies", []):
                    if tech not in self.s.technologies:
                        self.s.technologies.append(tech)
                if status in [401, 403]:
                    self.s.add_finding(Finding(
                        title=f"Restricted endpoint: {url} ({status})",
                        severity="low",
                        description=f"Returns {status} — may be bypassable.",
                        url=url, module="integrations.httpx"
                    ))
            print(C.ok(f"httpx probed {len(lines)} hosts"))
        except Exception as e:
            print(C.warn(f"Could not parse httpx output: {e}"))

    # ── gau ───────────────────────────────────────────────────────────────────
    def run_gau(self):
        print(C.section("GAU — GET ALL URLS"))
        if not _check_tool("gau"):
            print(C.info("Install: go install github.com/lc/gau/v2/cmd/gau@latest"))
            return

        out_txt = str(self.out / "gau_output.txt")
        cmd = ["gau", "--o", out_txt, self.s.domain]
        _run(cmd, timeout=300)
        if Path(out_txt).exists():
            urls = [u.strip() for u in Path(out_txt).read_text().splitlines() if u.strip()]
            for url in urls:
                self.s.add_url(url)
            self._flag_interesting_urls(urls, "integrations.gau")
            print(C.ok(f"gau found {len(urls)} URLs"))

    # ── waybackurls ───────────────────────────────────────────────────────────
    def run_waybackurls(self):
        print(C.section("WAYBACKURLS"))
        if not _check_tool("waybackurls"):
            print(C.info("Install: go install github.com/tomnomnom/waybackurls@latest"))
            return

        out_txt = str(self.out / "waybackurls_output.txt")
        print(C.info(f"Running: waybackurls {self.s.domain}"))
        try:
            result = subprocess.run(
                ["waybackurls", self.s.domain],
                capture_output=True, text=True, timeout=300
            )
            urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
            Path(out_txt).write_text("\n".join(urls))
            for url in urls:
                self.s.add_url(url)
            self._flag_interesting_urls(urls, "integrations.waybackurls")
            print(C.ok(f"waybackurls found {len(urls)} URLs"))
        except Exception as e:
            print(C.err(f"waybackurls failed: {e}"))

    def _flag_interesting_urls(self, urls, module):
        """Flag URLs with sensitive extensions or keywords."""
        sensitive_exts = [".env", ".git", ".sql", ".bak", ".backup", ".config",
                          ".log", ".key", ".pem", ".yaml", ".yml"]
        sensitive_kw   = ["password", "secret", "token", "apikey", "api_key",
                          "access_key", "admin", "debug", "internal", "passwd"]
        for url in urls:
            url_lower = url.lower()
            for ext in sensitive_exts:
                if url_lower.endswith(ext) or f"{ext}?" in url_lower:
                    self.s.add_finding(Finding(
                        title=f"Sensitive file in URL history: {url}",
                        severity="medium",
                        description=f"Historical URL with sensitive extension '{ext}'.",
                        url=url, module=module
                    ))
                    break
            else:
                for kw in sensitive_kw:
                    if kw in url_lower:
                        self.s.add_finding(Finding(
                            title=f"Sensitive keyword in URL: {url}",
                            severity="low",
                            description=f"URL contains keyword '{kw}'.",
                            url=url, module=module
                        ))
                        break

    # ── dirsearch ─────────────────────────────────────────────────────────────
    def run_dirsearch(self, target=None, wordlist=None, extensions=None):
        print(C.section("DIRSEARCH DIRECTORY ENUMERATION"))
        if not _check_tool("dirsearch"):
            print(C.info("Install: pip install dirsearch"))
            return

        target = target or self.s.target
        ext = extensions or "php,html,js,txt,json,bak,zip,sql,log,xml,yaml,config"
        out_json = str(self.out / "dirsearch_output.json")
        cmd = ["dirsearch", "-u", target, "-e", ext, "-o", out_json, "--format=json",
               "--quiet", "-t", "20"]
        if wordlist:
            cmd += ["-w", wordlist]

        _run(cmd, timeout=600)
        if Path(out_json).exists():
            self._parse_dirsearch_json(out_json)

    def _parse_dirsearch_json(self, json_path):
        try:
            data = json.loads(Path(json_path).read_text())
            results = data.get("results", [])
            for r in results:
                url = r.get("url", "")
                status = r.get("status", 0)
                if url:
                    self.s.add_url(url)
                sensitive_kw = ["admin", "backup", ".git", ".env", "config",
                                "debug", "swagger", "upload", "secret", "api"]
                if status in [200, 201, 204] and any(k in url.lower() for k in sensitive_kw):
                    self.s.add_finding(Finding(
                        title=f"Sensitive path found: {url}",
                        severity="medium",
                        description=f"dirsearch found accessible sensitive path (HTTP {status})",
                        url=url, module="integrations.dirsearch"
                    ))
            print(C.ok(f"dirsearch found {len(results)} paths"))
        except Exception as e:
            print(C.warn(f"Could not parse dirsearch output: {e}"))

    # ── linkfinder ────────────────────────────────────────────────────────────
    def run_linkfinder(self, target=None):
        print(C.section("LINKFINDER JS ENDPOINT EXTRACTION"))
        lf_path = shutil.which("linkfinder") or shutil.which("linkfinder.py")
        if not lf_path:
            for p in ["/opt/linkfinder/linkfinder.py",
                      str(Path.home() / "tools/linkfinder/linkfinder.py")]:
                if Path(p).exists():
                    lf_path = p
                    break
        if not lf_path:
            print(C.warn("linkfinder not found."))
            print(C.info("Install: pip install linkfinder  or  git clone https://github.com/GerbenJavado/LinkFinder"))
            return

        target = target or self.s.target
        out_txt = str(self.out / "linkfinder_output.txt")
        cmd = ["python", lf_path, "-i", target, "-o", "cli", "-d"]
        rc, output = _run(cmd, timeout=120)
        endpoints = re.findall(r'https?://[^\s\'"<>]+|/[a-zA-Z0-9_/.-]+(?:\?[^\s\'"<>]*)?', output)
        for ep in endpoints:
            full = ep if ep.startswith("http") else f"{target.rstrip('/')}{ep}"
            self.s.add_url(full)
        Path(out_txt).write_text(output)
        print(C.ok(f"linkfinder extracted {len(endpoints)} endpoints"))

    # ── arjun ─────────────────────────────────────────────────────────────────
    def run_arjun(self, target=None):
        print(C.section("ARJUN PARAMETER DISCOVERY"))
        if not _check_tool("arjun"):
            print(C.info("Install: pip install arjun"))
            return

        target = target or self.s.target
        out_json = str(self.out / "arjun_output.json")
        cmd = ["arjun", "-u", target, "--stable", "-oJ", out_json, "-t", "10"]
        _run(cmd, timeout=300)
        if Path(out_json).exists():
            try:
                data = json.loads(Path(out_json).read_text())
                params = data.get(target, {}).get("params", [])
                if params:
                    self.s.add_finding(Finding(
                        title=f"Hidden parameters discovered: {target}",
                        severity="info",
                        description=f"Arjun found {len(params)} hidden params: {', '.join(params)}",
                        url=target, evidence=str(params), module="integrations.arjun"
                    ))
                print(C.ok(f"arjun found {len(params)} parameters"))
            except Exception as e:
                print(C.warn(f"Could not parse arjun output: {e}"))

    # ── dalfox ────────────────────────────────────────────────────────────────
    def run_dalfox(self, target=None):
        print(C.section("DALFOX XSS SCANNER"))
        if not _check_tool("dalfox"):
            print(C.info("Install: go install github.com/hahwul/dalfox/v2@latest"))
            return

        target = target or self.s.target
        out_json = str(self.out / "dalfox_output.json")
        cmd = ["dalfox", "url", target,
               "--report", "--report-format", "json",
               "--report-file-path", out_json,
               "--silence", "--no-spinner"]
        _run(cmd, timeout=300)
        if Path(out_json).exists():
            self._parse_dalfox_json(out_json)

    def _parse_dalfox_json(self, json_path):
        try:
            data = json.loads(Path(json_path).read_text())
            issues = data if isinstance(data, list) else data.get("results", [])
            for issue in issues:
                self.s.add_finding(Finding(
                    title=f"[dalfox] XSS: {issue.get('param', 'unknown param')}",
                    severity="high",
                    description=issue.get("message", "XSS detected by dalfox"),
                    url=issue.get("url", ""),
                    evidence=issue.get("poc", ""),
                    module="integrations.dalfox"
                ))
            print(C.ok(f"dalfox found {len(issues)} XSS issues"))
        except Exception as e:
            print(C.warn(f"Could not parse dalfox output: {e}"))

    # ── sqlmap ────────────────────────────────────────────────────────────────
    def run_sqlmap(self, target=None, data=None, level=1, risk=1):
        print(C.section("SQLMAP SQL INJECTION SCANNER"))
        if not _check_tool("sqlmap"):
            print(C.info("Install: pip install sqlmap  or  apt install sqlmap"))
            return

        target = target or self.s.target
        out_dir = str(self.out / "sqlmap")
        cmd = [
            "sqlmap", "-u", target,
            "--batch", "--output-dir", out_dir,
            "--level", str(level), "--risk", str(risk),
            "--random-agent", "--forms", "--crawl=2",
        ]
        if data:
            cmd += ["--data", data]

        rc, output = _run(cmd, timeout=600)
        # Parse findings from streamed output
        vuln_patterns = [
            r"(Parameter '.+?' is vulnerable.*)",
            r"(sqlmap identified the following injection point.*)",
            r"(back-end DBMS: .+)",
        ]
        seen = set()
        for pattern in vuln_patterns:
            for match in re.findall(pattern, output, re.IGNORECASE):
                if match not in seen:
                    seen.add(match)
                    self.s.add_finding(Finding(
                        title="[sqlmap] SQL Injection detected",
                        severity="critical",
                        description=match,
                        url=target, module="integrations.sqlmap"
                    ))
        print(C.ok(f"sqlmap scan complete. Results in: {out_dir}"))

    # ── jaeles ────────────────────────────────────────────────────────────────
    def run_jaeles(self, target=None, signatures=None):
        print(C.section("JAELES WEB SECURITY SCANNER"))
        if not _check_tool("jaeles"):
            print(C.info("Install: go install github.com/jaeles-project/jaeles@latest"))
            return

        target = target or self.s.target
        out_dir = str(self.out / "jaeles")
        cmd = ["jaeles", "scan", "-u", target, "--output", out_dir, "--verbose"]
        if signatures:
            cmd += ["-s", signatures]

        _run(cmd, timeout=600)
        out_path = Path(out_dir)
        if out_path.exists():
            for report_file in out_path.glob("*.txt"):
                content = report_file.read_text(errors="ignore")
                if re.search(r"vulnerable|vuln|Vuln", content):
                    self.s.add_finding(Finding(
                        title=f"[jaeles] Finding in {report_file.name}",
                        severity="medium",
                        description=content[:500],
                        url=target, module="integrations.jaeles"
                    ))
        print(C.ok(f"jaeles complete. Results in: {out_dir}"))

    # ── 403bypasser ───────────────────────────────────────────────────────────
    def run_403bypasser(self, target=None, path=None):
        print(C.section("403BYPASSER ACCESS CONTROL BYPASS"))
        bypasser_path = shutil.which("403bypasser") or shutil.which("403bypasser.py")
        if not bypasser_path:
            for p in ["/opt/403bypasser/403bypasser.py",
                      str(Path.home() / "tools/403bypasser/403bypasser.py")]:
                if Path(p).exists():
                    bypasser_path = p
                    break
        if not bypasser_path:
            print(C.warn("403bypasser not found."))
            print(C.info("Install: git clone https://github.com/yunemse48/403bypasser"))
            return

        target = target or self.s.target
        test_paths = [path] if path else ["/admin", "/admin/", "/dashboard", "/config", "/.env"]
        for test_path in test_paths:
            cmd = ["python", bypasser_path, "-u", target.rstrip("/"), "-p", test_path]
            rc, output = _run(cmd, timeout=60)
            if "200" in output or "bypass" in output.lower():
                self.s.add_finding(Finding(
                    title=f"403 Bypass possible: {target}{test_path}",
                    severity="high",
                    description=f"403bypasser found bypass on '{test_path}'.",
                    url=f"{target.rstrip('/')}{test_path}",
                    evidence=output[:500], module="integrations.403bypasser"
                ))

    # ── keye ──────────────────────────────────────────────────────────────────
    def run_keye(self, target=None):
        print(C.section("KEYE WEB CRAWLER"))
        if not _check_tool("keye"):
            print(C.info("Install: pip install keye  or  https://github.com/s0md3v/Keye"))
            return

        target = target or self.s.target
        out_txt = str(self.out / "keye_output.txt")
        cmd = ["keye", "-u", target, "-l", "2", "--silent"]
        rc, output = _run(cmd, timeout=300)
        urls = re.findall(r'https?://[^\s\'"<>]+', output)
        for url in urls:
            self.s.add_url(url)
        Path(out_txt).write_text(output)
        print(C.ok(f"keye crawled {len(urls)} URLs"))

    # ── shodan ────────────────────────────────────────────────────────────────
    def run_shodan(self, api_key=None):
        print(C.section("SHODAN INTELLIGENCE"))
        if not _check_tool("shodan"):
            print(C.info("Install: pip install shodan"))
            return

        if api_key:
            subprocess.run(["shodan", "init", api_key], capture_output=True)

        out_txt = str(self.out / "shodan_output.txt")
        cmd = ["shodan", "search", "--fields",
               "ip_str,port,org,os,product,version",
               "--separator", ",", f"hostname:{self.s.domain}"]
        rc, output = _run(cmd, timeout=60)
        if output:
            Path(out_txt).write_text(output)
            lines = [l for l in output.splitlines() if l.strip() and "," in l]
            for line in lines:
                parts = line.split(",")
                ip = parts[0].strip()
                port_str = parts[1].strip() if len(parts) > 1 else ""
                product = parts[4].strip() if len(parts) > 4 else ""
                version = parts[5].strip() if len(parts) > 5 else ""
                try:
                    port = int(port_str)
                    self.s.open_ports.setdefault(ip, [])
                    if port not in self.s.open_ports[ip]:
                        self.s.open_ports[ip].append(port)
                except ValueError:
                    pass
                if product:
                    self.s.add_finding(Finding(
                        title=f"Shodan: {ip}:{port_str} — {product} {version}".strip(),
                        severity="info",
                        description=f"Service on {ip}:{port_str}. Org: {parts[2].strip() if len(parts) > 2 else 'N/A'}",
                        url=f"http://{ip}:{port_str}",
                        module="integrations.shodan"
                    ))
            print(C.ok(f"shodan returned {len(lines)} results"))

    # ── keyleak ───────────────────────────────────────────────────────────────
    def run_keyleak(self, scan_path=None):
        print(C.section("KEYLEAK — API KEY & SECRET DETECTOR"))
        keyleak_path = shutil.which("keyleak") or shutil.which("keyleak-detector")
        if not keyleak_path:
            for p in ["/opt/keyleak-detector/keyleak.py",
                      str(Path.home() / "tools/keyleak-detector/keyleak.py")]:
                if Path(p).exists():
                    keyleak_path = p
                    break

        if keyleak_path:
            target_arg = scan_path or str(self.out)
            cmd = ["python", keyleak_path, "--path", target_arg]
            rc, output = _run(cmd, timeout=120)
            for match in re.findall(r'(?:Found|Detected|LEAK)\s*[:\-]?\s*(.+)', output, re.IGNORECASE):
                self.s.add_finding(Finding(
                    title="Potential secret/key leak detected",
                    severity="high",
                    description=match.strip(),
                    module="integrations.keyleak"
                ))
        else:
            print(C.info("keyleak-detector not found — running built-in regex scan on collected data."))
            print(C.info("Install: git clone https://github.com/Amal-David/keyleak-detector"))
            self._keyleak_regex_scan()

    def _keyleak_regex_scan(self):
        """Built-in regex-based secret scan on collected output files and URLs."""
        SECRET_PATTERNS = {
            "AWS Access Key":     r"AKIA[0-9A-Z]{16}",
            "GitHub Token":       r"ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82}",
            "Google API Key":     r"AIza[0-9A-Za-z\-_]{35}",
            "Slack Token":        r"xox[baprs]-[0-9a-zA-Z\-]+",
            "JWT Token":          r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "Private Key Header": r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
            "Stripe Secret Key":  r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
            "SendGrid Key":       r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
            "Generic Secret":     r"(?i)(?:secret|password|api[_-]?key|token)\s*[=:\"']\s*['\"]?([A-Za-z0-9+/=_\-]{16,})",
        }
        scan_content = "\n".join(self.s.urls)
        for output_file in self.out.glob("*"):
            if output_file.is_file() and output_file.suffix in [".txt", ".json", ".html", ".xml"]:
                try:
                    scan_content += "\n" + output_file.read_text(errors="ignore")
                except Exception:
                    pass

        found = 0
        for key_type, pattern in SECRET_PATTERNS.items():
            for match in re.findall(pattern, scan_content):
                evidence = match if isinstance(match, str) else (match[-1] if match else "")
                self.s.add_finding(Finding(
                    title=f"Potential secret leak: {key_type}",
                    severity="critical",
                    description=f"Pattern matched for '{key_type}' in collected output data.",
                    evidence=evidence[:80], module="integrations.keyleak"
                ))
                found += 1
        print(C.ok(f"keyleak regex scan complete — {found} potential secrets found"))

    # ── wappalyzer ────────────────────────────────────────────────────────────
    def run_wappalyzer(self, target=None):
        print(C.section("WAPPALYZER TECHNOLOGY FINGERPRINTING"))
        target = target or self.s.target
        wap_cmd = shutil.which("wappalyzer")
        if wap_cmd:
            out_json = str(self.out / "wappalyzer_output.json")
            rc, output = _run(["wappalyzer", target, "--pretty"], timeout=60)
            try:
                data = json.loads(output)
                techs = data.get("technologies", [])
                for tech in techs:
                    name = tech.get("name", "")
                    version = tech.get("version", "")
                    label = f"{name} {version}".strip()
                    if name and label not in self.s.technologies:
                        self.s.technologies.append(label)
                        print(C.ok(f"  Tech: {label}"))
                print(C.ok(f"wappalyzer detected {len(techs)} technologies"))
                return
            except Exception:
                Path(out_json).write_text(output)

        # Fallback: python-Wappalyzer library
        try:
            from Wappalyzer import Wappalyzer, WebPage
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(target)
            techs = wappalyzer.analyze_with_versions(webpage)
            for name, info in techs.items():
                version = (info.get("versions") or [""])[0]
                label = f"{name} {version}".strip()
                if label not in self.s.technologies:
                    self.s.technologies.append(label)
                    print(C.ok(f"  Tech: {label}"))
            print(C.ok(f"python-Wappalyzer detected {len(techs)} technologies"))
        except ImportError:
            print(C.warn("Wappalyzer CLI or python-Wappalyzer not found."))
            print(C.info("Install CLI: npm install -g wappalyzer"))
            print(C.info("Install lib: pip install python-Wappalyzer"))
        except Exception as e:
            print(C.warn(f"Wappalyzer failed: {e}"))

    # ── google dorking ────────────────────────────────────────────────────────
    DORK_TEMPLATES = [
        "site:{d} filetype:env OR filetype:log OR filetype:sql OR filetype:bak",
        "site:{d} inurl:admin OR inurl:dashboard OR inurl:panel OR inurl:portal",
        'site:{d} intext:"DB_PASSWORD" OR intext:"API_KEY" OR intext:"SECRET_KEY"',
        "site:{d} inurl:config OR inurl:setup OR inurl:install OR inurl:phpinfo",
        'site:{d} intitle:"index of"',
        "site:{d} inurl:.git OR inurl:.svn OR inurl:.DS_Store",
        "site:{d} ext:php inurl:?id= OR inurl:?page= OR inurl:?file=",
        "site:{d} inurl:api/v1 OR inurl:api/v2 OR inurl:swagger OR inurl:graphql",
        '"@{d}" filetype:xls OR filetype:csv OR filetype:xlsx',
        'site:{d} "phpinfo()" OR "wp-config" OR "web.config"',
        "site:{d} inurl:upload OR inurl:uploads OR inurl:file",
        "site:{d} inurl:backup OR inurl:old OR inurl:archive OR inurl:legacy",
        "site:{d} inurl:redirect= OR inurl:url= OR inurl:return= OR inurl:next=",
        'site:{d} -www',
        'site:{d} inurl:debug OR inurl:trace OR inurl:test OR inurl:dev',
    ]

    def run_google_dork(self, api_key=None, cx=None):
        print(C.section("GOOGLE DORKING"))
        domain = self.s.domain
        dorks = [t.replace("{d}", domain) for t in self.DORK_TEMPLATES]
        out_txt = str(self.out / "google_dorks.txt")
        Path(out_txt).write_text("\n".join(dorks))
        print(C.ok(f"Generated {len(dorks)} dorks — saved to: {out_txt}"))

        if not api_key or not cx:
            print(C.info("Pass --google-key and --google-cx to auto-search via Google Custom Search API."))
            print(C.info("Manual: copy dork queries from the output file into Google."))
            for dork in dorks:
                print(f"  {C.DIM}{dork}{C.RESET}")
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        results = []
        for dork in dorks[:5]:  # Stay within free API quota
            encoded = urllib.parse.quote(dork)
            url = (f"https://www.googleapis.com/customsearch/v1"
                   f"?key={api_key}&cx={cx}&q={encoded}")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 BBRecon/1.0"})
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    data = json.loads(resp.read())
                for item in data.get("items", []):
                    result_url = item.get("link", "")
                    if result_url:
                        self.s.add_url(result_url)
                        results.append(result_url)
                        self.s.add_finding(Finding(
                            title=f"Google Dork result: {item.get('title', result_url)}",
                            severity="info",
                            description=f"Dork: {dork}\nSnippet: {item.get('snippet', '')}",
                            url=result_url, module="integrations.google_dork"
                        ))
            except Exception as e:
                print(C.warn(f"Google API error: {e}"))
        print(C.ok(f"Google dorking found {len(results)} results"))

    # ── BurpSuite Enterprise (REST API) ───────────────────────────────────────
    def run_burpsuite(self, base_url=None, api_key=None):
        print(C.section("BURPSUITE ENTERPRISE SCAN"))
        if not base_url or not api_key:
            print(C.warn("BurpSuite Enterprise requires --burp-url and --burp-key."))
            print(C.info("BurpSuite Pro users: run manually and import results."))
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {"Authorization": f"token {api_key}", "Content-Type": "application/json"}
        payload = json.dumps({
            "scope": {"include": [{"rule": self.s.target}]},
            "scan_configurations": [{"name": "Crawl and Audit - Balanced"}],
        }).encode()
        try:
            req = urllib.request.Request(
                f"{base_url.rstrip('/')}/api/v1/scan",
                data=payload, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                data = json.loads(resp.read())
            scan_id = data.get("id", "")
            print(C.ok(f"BurpSuite scan created. ID: {scan_id}"))
            self.s.notes.append(f"BurpSuite scan ID: {scan_id} — check {base_url} for results")
        except Exception as e:
            print(C.err(f"BurpSuite API error: {e}"))

    # ── Acunetix (REST API) ───────────────────────────────────────────────────
    def run_acunetix(self, base_url=None, api_key=None):
        print(C.section("ACUNETIX SCAN"))
        if not base_url or not api_key:
            print(C.warn("Acunetix requires --acunetix-url (e.g. https://localhost:3443) and --acunetix-key."))
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {"X-Auth": api_key, "Content-Type": "application/json"}
        base = base_url.rstrip("/")
        try:
            # Add target
            t_payload = json.dumps({"address": self.s.target, "description": "BBRecon"}).encode()
            req = urllib.request.Request(f"{base}/api/v1/targets",
                                         data=t_payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                target_id = json.loads(resp.read()).get("target_id", "")

            # Start scan (Full Scan profile UUID)
            s_payload = json.dumps({
                "target_id": target_id,
                "profile_id": "11111111-1111-1111-1111-111111111111",
            }).encode()
            req2 = urllib.request.Request(f"{base}/api/v1/scans",
                                          data=s_payload, headers=headers, method="POST")
            with urllib.request.urlopen(req2, context=ctx, timeout=30) as resp2:
                scan_id = json.loads(resp2.read()).get("scan_id", "")
            print(C.ok(f"Acunetix scan started. Scan ID: {scan_id}"))
            self.s.notes.append(f"Acunetix scan ID: {scan_id} — check {base_url} for results")
        except Exception as e:
            print(C.err(f"Acunetix API error: {e}"))

    # ── Nessus (REST API) ─────────────────────────────────────────────────────
    def run_nessus(self, base_url=None, access_key=None, secret_key=None):
        print(C.section("NESSUS VULNERABILITY SCAN"))
        if not base_url or not access_key or not secret_key:
            print(C.warn("Nessus requires --nessus-url, --nessus-access-key, and --nessus-secret-key."))
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
        }
        base = base_url.rstrip("/")
        try:
            # Create scan (Basic Network Scan template UUID)
            payload = json.dumps({
                "uuid": "ad629e16-7b6e-11d9-a153-0800200c9a66",
                "settings": {"name": f"BBRecon — {self.s.domain}", "text_targets": self.s.domain},
            }).encode()
            req = urllib.request.Request(f"{base}/scans",
                                         data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                scan_id = json.loads(resp.read()).get("scan", {}).get("id", "")

            # Launch scan
            req2 = urllib.request.Request(f"{base}/scans/{scan_id}/launch",
                                          data=b"{}", headers=headers, method="POST")
            urllib.request.urlopen(req2, context=ctx, timeout=30)
            print(C.ok(f"Nessus scan launched. Scan ID: {scan_id}"))
            self.s.notes.append(f"Nessus scan ID: {scan_id} — check {base_url} for results")
        except Exception as e:
            print(C.err(f"Nessus API error: {e}"))
