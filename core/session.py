"""Session: central state for a bug bounty engagement."""
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from core.banner import C


class Finding:
    SEVERITIES = ["critical", "high", "medium", "low", "info"]

    def __init__(self, title, severity, description, url="", evidence="", module=""):
        assert severity in self.SEVERITIES, f"Invalid severity: {severity}"
        self.title       = title
        self.severity    = severity
        self.description = description
        self.url         = url
        self.evidence    = evidence
        self.module      = module
        self.timestamp   = datetime.now().isoformat()

    def to_dict(self):
        return self.__dict__

    def __str__(self):
        sev_color = {
            "critical": C.RED + C.BOLD,
            "high":     C.RED,
            "medium":   C.YELLOW,
            "low":      C.CYAN,
            "info":     C.DIM,
        }[self.severity]
        return (
            f"  {sev_color}[{self.severity.upper()}]{C.RESET} {self.title}\n"
            f"  {C.DIM}URL: {self.url}{C.RESET}\n"
            f"  {self.description}"
        )


class Session:
    def __init__(self, target: str, output_dir: str = "./output", verbose: bool = False):
        # Normalize target
        self.target_raw  = target
        self.target      = self._normalize(target)
        self.output_dir  = Path(output_dir) / self._target_slug()
        self.verbose     = verbose
        self.start_time  = datetime.now()
        self.findings    : list[Finding] = []
        self.subdomains  : list[str]     = []
        self.open_ports  : dict          = {}   # host -> [ports]
        self.technologies: list[str]     = []
        self.urls        : list[str]     = []   # discovered endpoints
        self.scope       : list[str]     = []
        self.notes       : list[str]     = []
        self.dns_records : dict          = {}   # host -> [ip, ...]
        self.parameters  : dict          = {}   # url -> [param_names]
        self.js_files    : list[str]     = []
        self.forms       : list[dict]    = []

        self.output_dir.mkdir(parents=True, exist_ok=True)
        print(C.info(f"Session started for: {C.BOLD}{self.target}{C.RESET}"))
        print(C.info(f"Output dir: {self.output_dir}\n"))

    def _normalize(self, target: str) -> str:
        if not target.lower().startswith(("http://", "https://")):
            return f"https://{target}"
        return target

    def _target_slug(self) -> str:
        parsed = urlparse(self.target)
        host = parsed.netloc or parsed.path
        path = parsed.path.strip("/")
        raw = host if not path else f"{host}_{path}"
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", raw).strip("_")
        return slug or "target"

    @property
    def domain(self) -> str:
        """Returns bare domain without scheme."""
        parsed = urlparse(self.target)
        return parsed.netloc or parsed.path.rstrip("/")

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        print(C.vuln(f"{C.BOLD}{finding.title}{C.RESET} [{finding.severity.upper()}]"))
        if self.verbose:
            print(str(finding))

    def add_subdomain(self, sub: str):
        if sub not in self.subdomains:
            self.subdomains.append(sub)
            print(C.ok(f"Subdomain: {sub}"))

    def add_url(self, url: str):
        if url not in self.urls:
            self.urls.append(url)

    def log(self, msg: str):
        print(C.info(msg))

    def ok(self, msg: str):
        print(C.ok(msg))

    def warn(self, msg: str):
        print(C.warn(msg))

    def err(self, msg: str):
        print(C.err(msg))

    def summary(self):
        print(C.section("SESSION SUMMARY"))
        elapsed = (datetime.now() - self.start_time).seconds
        print(f"  Target      : {self.target}")
        print(f"  Duration    : {elapsed}s")
        print(f"  Subdomains  : {len(self.subdomains)}")
        print(f"  URLs found  : {len(self.urls)}")
        print(f"  Findings    : {len(self.findings)}")

        by_sev = {}
        for f in self.findings:
            by_sev.setdefault(f.severity, []).append(f)

        for sev in Finding.SEVERITIES:
            if sev in by_sev:
                print(f"    {sev.upper():<10}: {len(by_sev[sev])}")

        if self.findings:
            print(C.section("FINDINGS"))
            for f in self.findings:
                print(str(f))

    def save(self):
        data = {
            "target":       self.target,
            "start_time":   self.start_time.isoformat(),
            "subdomains":   self.subdomains,
            "urls":         self.urls[:500],
            "technologies": self.technologies,
            "open_ports":   self.open_ports,
            "dns_records":  self.dns_records,
            "parameters":   self.parameters,
            "js_files":     self.js_files,
            "forms":        self.forms,
            "findings":     [f.to_dict() for f in self.findings],
        }
        out = self.output_dir / "session.json"
        out.write_text(json.dumps(data, indent=2))
        print(C.ok(f"Session saved: {out}"))
        self.summary()
