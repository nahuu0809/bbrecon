"""Finding validator — verifies vulnerabilities to reduce false positives."""
import re
from urllib.parse import urlparse, parse_qs, urlencode
from core.banner import C
from core.session import Finding
from core import http_client


class ValidationResult:
    __slots__ = ("finding", "verified", "confidence", "reason", "poc")

    def __init__(self, finding: Finding, verified: bool, confidence: float,
                 reason: str, poc: str = ""):
        self.finding = finding
        self.verified = verified
        self.confidence = confidence  # 0.0 to 1.0
        self.reason = reason
        self.poc = poc


def _redirect_target_matches(value: str, target_host: str = "evil.com") -> bool:
    normalized = value.lower().replace("。", ".").replace("\\", "/")
    return target_host in normalized


def _is_client_side_redirect(body: str, target_host: str = "evil.com") -> bool:
    lower = body.lower()
    if not _redirect_target_matches(lower, target_host):
        return False
    redirect_markers = (
        "location.href",
        "window.location",
        "window.open(",
        'http-equiv="refresh"',
        "http-equiv='refresh'",
    )
    return any(marker in lower for marker in redirect_markers)


class Validator:
    """Re-tests reported findings to confirm they are real vulnerabilities."""

    def __init__(self, session):
        self.s = session
        self.results: list[ValidationResult] = []
        self.confirmed: list[Finding] = []
        self.rejected: list[Finding] = []

    def validate_all(self):
        """Validate all findings in the current session."""
        print(C.section("FINDING VALIDATION"))
        findings = self.s.findings
        print(C.info(f"Validating {len(findings)} findings..."))

        for finding in findings:
            result = self._validate(finding)
            self.results.append(result)
            if result.verified:
                self.confirmed.append(finding)
            else:
                self.rejected.append(finding)

        # Summary
        print(C.ok(f"Validation complete:"))
        print(C.ok(f"  Confirmed : {len(self.confirmed)}"))
        print(C.warn(f"  Rejected  : {len(self.rejected)}"))

        # Update findings with confidence
        for result in self.results:
            if result.poc:
                result.finding.evidence = (
                    f"{result.finding.evidence}\n"
                    f"[Validated: confidence={result.confidence:.0%}] {result.reason}\n"
                    f"PoC: {result.poc}"
                )

        # Replace session findings with only confirmed ones + info-level
        self.s.findings = [
            f for f in self.s.findings
            if f in self.confirmed or f.severity == "info"
        ]

        return self.results

    def _validate(self, finding: Finding) -> ValidationResult:
        """Route validation to the appropriate checker."""
        module = finding.module.lower()

        if "xss" in module:
            return self._validate_xss(finding)
        elif "sqli" in module or "sqlmap" in module:
            return self._validate_sqli(finding)
        elif "ssrf" in module:
            return self._validate_ssrf(finding)
        elif "idor" in module:
            return self._validate_idor(finding)
        elif "lfi" in module:
            return self._validate_lfi(finding)
        elif "redirect" in module:
            return self._validate_redirect(finding)
        elif "header" in module or "probe" in module:
            # Info-level, auto-confirm
            return ValidationResult(finding, True, 0.9, "Info finding — auto-confirmed")
        else:
            # Can't validate — keep with low confidence
            return ValidationResult(finding, True, 0.5, "Unvalidated — kept as-is")

    def _validate_xss(self, finding: Finding) -> ValidationResult:
        """Verify XSS by re-sending payload and checking reflection."""
        url = finding.url
        if not url:
            return ValidationResult(finding, False, 0.0, "No URL to re-test")

        resp = http_client.get(url, timeout=6.0)
        if resp.error:
            return ValidationResult(finding, False, 0.0, f"Request failed: {resp.error}")

        # Extract payload from description/evidence
        payload_match = re.search(r"Payload:\s*(.+)", finding.description)
        payload = payload_match.group(1).strip() if payload_match else ""

        if payload and payload in resp.body:
            # Double-check: is the payload actually in a dangerous context?
            # Check if it's inside an HTML tag or script context
            dangerous_contexts = [
                f"<script>{re.escape(payload)}</script>",
                f'onerror={re.escape(payload)}',
                f'onload={re.escape(payload)}',
                re.escape(payload),  # any reflection
            ]
            for ctx in dangerous_contexts:
                if re.search(ctx, resp.body, re.IGNORECASE):
                    return ValidationResult(
                        finding, True, 0.95,
                        "Payload reflected in response body",
                        poc=f"curl -s '{url}' | grep -o '{payload[:30]}'"
                    )

        # Check if page encodes the payload (false positive)
        import html
        if payload and html.escape(payload) in resp.body and payload not in resp.body:
            return ValidationResult(finding, False, 0.1, "Payload is HTML-encoded — not exploitable")

        return ValidationResult(finding, False, 0.3, "Payload not reflected on re-test")

    def _validate_sqli(self, finding: Finding) -> ValidationResult:
        """Verify SQLi by re-testing with a different payload variation."""
        url = finding.url
        if not url:
            return ValidationResult(finding, False, 0.0, "No URL to re-test")

        # Re-send the original request
        resp = http_client.get(url, timeout=6.0)
        if resp.error:
            return ValidationResult(finding, False, 0.0, f"Request failed: {resp.error}")

        sqli_errors = [
            r"you have an error in your sql syntax",
            r"warning: mysql", r"unclosed quotation mark",
            r"syntax error.*postgresql", r"ORA-\d{5}",
            r"ODBC.*Driver", r"SQLite.*error",
        ]

        for pattern in sqli_errors:
            if re.search(pattern, resp.body, re.IGNORECASE):
                # Confirmed — try a second variation to double-verify
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param in params:
                    safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode({param: ['1']})}"
                    safe_resp = http_client.get(safe_url, timeout=6.0)
                    if safe_resp.error:
                        continue
                    # If clean request doesn't trigger error, SQLi is real
                    if not any(re.search(p, safe_resp.body, re.IGNORECASE) for p in sqli_errors):
                        return ValidationResult(
                            finding, True, 0.95,
                            "SQL error triggered by payload but not by clean input",
                            poc=f"curl -s '{url}'"
                        )

                return ValidationResult(finding, True, 0.7, "SQL error present in response")

        return ValidationResult(finding, False, 0.2, "SQL error not present on re-test")

    def _validate_ssrf(self, finding: Finding) -> ValidationResult:
        """Verify SSRF by checking for internal content indicators."""
        url = finding.url
        if not url:
            return ValidationResult(finding, False, 0.0, "No URL to re-test")

        resp = http_client.get(url, timeout=6.0)
        if resp.error:
            return ValidationResult(finding, False, 0.0, f"Request failed: {resp.error}")

        indicators = [
            (r"root:.*:0:0:", "Internal file content (/etc/passwd)"),
            (r"ami-id", "AWS metadata exposed"),
            (r"instance-id", "Cloud metadata exposed"),
            (r"redis_version", "Internal Redis service"),
        ]

        for pattern, desc in indicators:
            if re.search(pattern, resp.body, re.IGNORECASE):
                return ValidationResult(
                    finding, True, 0.95, desc,
                    poc=f"curl -s '{url}'"
                )

        return ValidationResult(finding, False, 0.2, "SSRF indicator not found on re-test")

    def _validate_idor(self, finding: Finding) -> ValidationResult:
        """IDOR requires manual verification — flag for review."""
        return ValidationResult(
            finding, True, 0.6,
            "IDOR requires manual review — verify data belongs to another user",
        )

    def _validate_lfi(self, finding: Finding) -> ValidationResult:
        """Verify LFI by checking for file content indicators."""
        url = finding.url
        if not url:
            return ValidationResult(finding, False, 0.0, "No URL to re-test")

        resp = http_client.get(url, timeout=6.0)
        if resp.error:
            return ValidationResult(finding, False, 0.0, f"Request failed")

        lfi_indicators = [
            (r"root:.*:0:0:", "File content: /etc/passwd"),
            (r"\[fonts\]", "File content: win.ini"),
            (r"PD9waHA", "Base64 PHP source code"),
        ]

        for pattern, desc in lfi_indicators:
            if re.search(pattern, resp.body):
                return ValidationResult(
                    finding, True, 0.95, desc,
                    poc=f"curl -s '{url}'"
                )

        return ValidationResult(finding, False, 0.2, "LFI indicator not found on re-test")

    def _validate_redirect(self, finding: Finding) -> ValidationResult:
        """Verify open redirect via Location header or client-side redirects."""
        url = finding.url
        if not url:
            return ValidationResult(finding, False, 0.0, "No URL to re-test")

        resp = http_client.get(url, timeout=6.0, follow_redirects=False)
        if resp.error:
            return ValidationResult(finding, False, 0.0, "Request failed")

        location = resp.header("Location")
        if 300 <= resp.status < 400 and _redirect_target_matches(location):
            return ValidationResult(
                finding, True, 0.85,
                f"Redirect target returned in Location header: {location}",
                poc=f"curl -v '{url}'"
            )

        if _is_client_side_redirect(resp.body):
            return ValidationResult(
                finding, True, 0.75,
                "Client-side redirect target present in response body",
                poc=f"curl -s '{url}'"
            )

        return ValidationResult(finding, False, 0.3, "Redirect target not observed on re-test")

    def get_confirmed(self) -> list[Finding]:
        return self.confirmed
