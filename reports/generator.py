"""Report generator — outputs findings in Markdown and JSON with PoC and impact."""
import json
from datetime import datetime
from pathlib import Path
from core.banner import C
from core.session import Finding


# Impact descriptions by vulnerability type
IMPACT_MAP = {
    "xss": "An attacker can execute arbitrary JavaScript in the victim's browser, potentially stealing session cookies, credentials, or performing actions on behalf of the user.",
    "sqli": "An attacker can read, modify, or delete database contents. In severe cases, this can lead to full system compromise via OS command execution.",
    "ssrf": "An attacker can make the server issue requests to internal services, potentially accessing cloud metadata, internal APIs, or pivoting to internal infrastructure.",
    "idor": "An attacker can access resources belonging to other users by manipulating object references, leading to unauthorized data disclosure or modification.",
    "lfi": "An attacker can read arbitrary files from the server, potentially exposing source code, configuration files, credentials, or system data.",
    "open_redirect": "An attacker can redirect users to malicious websites using a trusted domain, enabling phishing attacks and credential theft.",
    "rce": "An attacker can execute arbitrary commands on the server, leading to full system compromise.",
    "secret": "Exposed secrets (API keys, tokens, credentials) can be used for unauthorized access to third-party services or internal systems.",
    "header": "Missing or misconfigured security headers reduce defense-in-depth protections against XSS, clickjacking, and other client-side attacks.",
}


def _guess_vuln_type(finding: Finding) -> str:
    """Infer vulnerability type from finding module/title."""
    text = f"{finding.module} {finding.title}".lower()
    for key in ["xss", "sqli", "ssrf", "idor", "lfi", "rce", "redirect", "secret"]:
        if key in text:
            return key
    if "sql" in text:
        return "sqli"
    if "header" in text or "cors" in text or "hsts" in text or "csp" in text:
        return "header"
    return ""


class ReportGenerator:
    def __init__(self, session):
        self.s = session

    def generate(self, fmt="md"):
        generators = {
            "md":   self._markdown,
            "json": self._json,
        }
        fn = generators.get(fmt, self._markdown)
        out_path = fn()
        print(C.ok(f"Report saved: {out_path}"))
        return out_path

    # ── Markdown ──────────────────────────────────────────────────────────────
    def _markdown(self):
        s = self.s
        duration = (datetime.now() - s.start_time).seconds
        lines = [
            f"# Bug Bounty Report: {s.target}",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Duration:** {duration}s",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Subdomains found | {len(s.subdomains)} |",
            f"| URLs discovered | {len(s.urls)} |",
            f"| Total findings | {len(s.findings)} |",
        ]

        by_sev: dict[str, list[Finding]] = {}
        for f in s.findings:
            by_sev.setdefault(f.severity, []).append(f)

        for sev in Finding.SEVERITIES:
            if sev in by_sev:
                lines.append(f"| {sev.capitalize()} | {len(by_sev[sev])} |")

        lines += ["", "---", "", "## Findings", ""]

        for sev in Finding.SEVERITIES:
            if sev not in by_sev:
                continue
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[sev]
            lines += [f"### {emoji} {sev.capitalize()}", ""]

            for f in by_sev[sev]:
                vuln_type = _guess_vuln_type(f)
                impact = IMPACT_MAP.get(vuln_type, "")

                lines += [
                    f"#### {f.title}",
                    "",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **Vulnerability** | {f.title} |",
                    f"| **Endpoint** | `{f.url}` |",
                    f"| **Severity** | {f.severity.upper()} |",
                    f"| **Module** | `{f.module}` |",
                    f"| **Timestamp** | {f.timestamp} |",
                    "",
                    f"**Description:**",
                    f"{f.description}",
                    "",
                ]

                if impact:
                    lines += [f"**Impact:**", f"{impact}", ""]

                if f.evidence:
                    lines += [
                        f"**Proof of Concept:**",
                        f"```",
                        f"{f.evidence}",
                        f"```",
                        "",
                    ]

                lines += ["---", ""]

        # Appendices
        if s.subdomains:
            lines += ["## Appendix A: Subdomains", ""]
            for sub in sorted(s.subdomains):
                lines.append(f"- `{sub}`")
            lines.append("")

        if s.technologies:
            lines += ["## Appendix B: Technologies", ""]
            for tech in s.technologies:
                lines.append(f"- {tech}")
            lines.append("")

        if s.open_ports:
            lines += ["## Appendix C: Open Ports", ""]
            for host, ports in s.open_ports.items():
                lines.append(f"- **{host}:** {', '.join(str(p) for p in ports)}")
            lines.append("")

        if s.dns_records:
            lines += ["## Appendix D: DNS Records", ""]
            for host, ips in list(s.dns_records.items())[:50]:
                lines.append(f"- `{host}` → {', '.join(ips)}")
            lines.append("")

        content = "\n".join(lines)
        out = s.output_dir / "report.md"
        out.write_text(content, encoding="utf-8")
        return out

    # ── JSON ──────────────────────────────────────────────────────────────────
    def _json(self):
        s = self.s
        findings_data = []
        for f in s.findings:
            vuln_type = _guess_vuln_type(f)
            findings_data.append({
                **f.to_dict(),
                "vuln_type": vuln_type,
                "impact": IMPACT_MAP.get(vuln_type, ""),
                "proof_of_concept": f.evidence,
            })

        data = {
            "target":       s.target,
            "generated":    datetime.now().isoformat(),
            "duration_s":   (datetime.now() - s.start_time).seconds,
            "summary": {
                "subdomains":   len(s.subdomains),
                "urls":         len(s.urls),
                "findings":     len(s.findings),
                "by_severity": {
                    sev: len([f for f in s.findings if f.severity == sev])
                    for sev in Finding.SEVERITIES
                    if any(f.severity == sev for f in s.findings)
                },
            },
            "findings":     findings_data,
            "subdomains":   s.subdomains,
            "urls":         s.urls[:500],
            "technologies": s.technologies,
            "open_ports":   s.open_ports,
            "dns_records":  s.dns_records,
            "parameters":   s.parameters,
        }
        out = s.output_dir / "report.json"
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return out
