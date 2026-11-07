"""Interactive menu for BBRecon."""
from core.banner import C


class InteractiveMenu:
    def __init__(self, session):
        self.s = session

    def run(self):
        while True:
            print(C.section("MAIN MENU"))
            options = [
                ("1", "Pipeline — full automated scan"),
                ("2", "Recon — subdomains, DNS, ports, tech, headers, HTTP probe"),
                ("3", "Discover — crawl, JS analysis, endpoint aggregation, params"),
                ("4", "Vuln  — XSS, SQLi, SSRF, IDOR, LFI, Open Redirect"),
                ("5", "Fuzz  — paths, params, headers, JSON bodies"),
                ("6", "Validate — verify findings, reduce false positives"),
                ("7", "Integrations — external tools"),
                ("8", "Report — generate findings report"),
                ("9", "Summary — show current session findings"),
                ("0", "Exit"),
            ]
            for key, label in options:
                print(f"  {C.BOLD}[{key}]{C.RESET} {label}")

            choice = input("\n[?] Select option: ").strip()

            if choice == "1":
                self._menu_pipeline()
            elif choice == "2":
                self._menu_recon()
            elif choice == "3":
                self._menu_discover()
            elif choice == "4":
                self._menu_vuln()
            elif choice == "5":
                self._menu_fuzz()
            elif choice == "6":
                self._menu_validate()
            elif choice == "7":
                self._menu_integrations()
            elif choice == "8":
                self._menu_report()
            elif choice == "9":
                self.s.summary()
            elif choice == "0":
                self.s.save()
                print(C.ok("Goodbye."))
                break
            else:
                print(C.warn("Invalid option"))

    # ── Pipeline ─────────────────────────────────────────────────────────────
    def _menu_pipeline(self):
        print(C.section("FULL PIPELINE"))
        print(C.info("Running: subdomains → DNS → probe → crawl → JS → "
                      "aggregate → params → vuln → fuzz → validate → report"))

        from modules.recon import ReconModule
        from modules.dns_resolver import DNSResolver
        from modules.http_probe import HttpProbe
        from modules.crawler import Crawler
        from modules.js_analyzer import JSAnalyzer
        from modules.endpoint_aggregator import EndpointAggregator
        from modules.param_discovery import ParamDiscovery
        from modules.vuln import VulnModule
        from modules.fuzzer import Fuzzer
        from modules.validator import Validator
        from reports.generator import ReportGenerator

        recon = ReconModule(self.s)
        recon.enumerate_subdomains()
        recon.port_scan()
        recon.detect_technologies()
        recon.analyze_headers()

        dns = DNSResolver(self.s)
        dns.resolve_all()

        probe = HttpProbe(self.s)
        probe.probe_all()

        crawler = Crawler(self.s)
        crawler.crawl()
        self.s.js_files = list(crawler.js_urls)
        self.s.forms = crawler.forms_found

        js = JSAnalyzer(self.s)
        js.analyze(self.s.js_files)

        agg = EndpointAggregator(self.s)
        agg.aggregate(crawler=crawler, js_analyzer=js)

        params = ParamDiscovery(self.s)
        params.discover(agg.get_parameterized_urls()[:10] or [self.s.target])
        self.s.parameters = params.discovered

        vuln = VulnModule(self.s)
        vuln.test_xss()
        vuln.test_sqli()
        vuln.test_ssrf()
        vuln.test_idor()
        vuln.test_lfi()
        vuln.test_open_redirect()

        fuzzer = Fuzzer(self.s)
        fuzzer.fuzz_paths()
        fuzzer.fuzz_params()
        fuzzer.fuzz_headers()

        validator = Validator(self.s)
        validator.validate_all()

        gen = ReportGenerator(self.s)
        gen.generate(fmt="md")
        gen.generate(fmt="json")

        self.s.save()

    # ── Recon ────────────────────────────────────────────────────────────────
    def _menu_recon(self):
        from modules.recon import ReconModule
        mod = ReconModule(self.s)
        print(C.section("RECON"))
        print(f"  {C.BOLD}[1]{C.RESET} Subdomain enumeration")
        print(f"  {C.BOLD}[2]{C.RESET} Port scan")
        print(f"  {C.BOLD}[3]{C.RESET} Technology detection")
        print(f"  {C.BOLD}[4]{C.RESET} HTTP header analysis")
        print(f"  {C.BOLD}[5]{C.RESET} DNS resolution")
        print(f"  {C.BOLD}[6]{C.RESET} HTTP probe")
        print(f"  {C.BOLD}[7]{C.RESET} All of the above")
        choice = input("[?] Select: ").strip()
        if choice in ("1", "7"):
            mod.enumerate_subdomains()
        if choice in ("2", "7"):
            mod.port_scan()
        if choice in ("3", "7"):
            mod.detect_technologies()
        if choice in ("4", "7"):
            mod.analyze_headers()
        if choice in ("5", "7"):
            from modules.dns_resolver import DNSResolver
            DNSResolver(self.s).resolve_all()
        if choice in ("6", "7"):
            from modules.http_probe import HttpProbe
            HttpProbe(self.s).probe_all()

    # ── Discover ─────────────────────────────────────────────────────────────
    def _menu_discover(self):
        print(C.section("DISCOVERY"))
        print(f"  {C.BOLD}[1]{C.RESET} Web crawl")
        print(f"  {C.BOLD}[2]{C.RESET} JS endpoint analysis")
        print(f"  {C.BOLD}[3]{C.RESET} Endpoint aggregation")
        print(f"  {C.BOLD}[4]{C.RESET} Parameter discovery")
        print(f"  {C.BOLD}[5]{C.RESET} All of the above")
        choice = input("[?] Select: ").strip()
        if choice in ("1", "5"):
            from modules.crawler import Crawler
            crawler = Crawler(self.s)
            crawler.crawl()
            self.s.js_files = list(crawler.js_urls)
            self.s.forms = crawler.forms_found
        if choice in ("2", "5"):
            from modules.js_analyzer import JSAnalyzer
            JSAnalyzer(self.s).analyze(self.s.js_files)
        if choice in ("3", "5"):
            from modules.endpoint_aggregator import EndpointAggregator
            EndpointAggregator(self.s).aggregate()
        if choice in ("4", "5"):
            from modules.param_discovery import ParamDiscovery
            ParamDiscovery(self.s).discover()

    # ── Vuln ─────────────────────────────────────────────────────────────────
    def _menu_vuln(self):
        from modules.vuln import VulnModule
        mod = VulnModule(self.s)
        print(C.section("VULNERABILITY TESTING"))
        print(f"  {C.BOLD}[1]{C.RESET} XSS")
        print(f"  {C.BOLD}[2]{C.RESET} SQL Injection")
        print(f"  {C.BOLD}[3]{C.RESET} SSRF")
        print(f"  {C.BOLD}[4]{C.RESET} IDOR")
        print(f"  {C.BOLD}[5]{C.RESET} LFI / Path Traversal")
        print(f"  {C.BOLD}[6]{C.RESET} Open Redirect")
        print(f"  {C.BOLD}[7]{C.RESET} All of the above")
        choice = input("[?] Select: ").strip()
        if choice in ("1", "7"):
            mod.test_xss()
        if choice in ("2", "7"):
            mod.test_sqli()
        if choice in ("3", "7"):
            mod.test_ssrf()
        if choice in ("4", "7"):
            mod.test_idor()
        if choice in ("5", "7"):
            mod.test_lfi()
        if choice in ("6", "7"):
            mod.test_open_redirect()

    # ── Fuzz ─────────────────────────────────────────────────────────────────
    def _menu_fuzz(self):
        from modules.fuzzer import Fuzzer
        fz = Fuzzer(self.s)
        print(C.section("FUZZING"))
        print(f"  {C.BOLD}[1]{C.RESET} Path fuzzing")
        print(f"  {C.BOLD}[2]{C.RESET} Parameter fuzzing")
        print(f"  {C.BOLD}[3]{C.RESET} Header fuzzing")
        print(f"  {C.BOLD}[4]{C.RESET} JSON body fuzzing")
        print(f"  {C.BOLD}[5]{C.RESET} All of the above")
        choice = input("[?] Select: ").strip()
        if choice in ("1", "5"):
            fz.fuzz_paths()
        if choice in ("2", "5"):
            fz.fuzz_params()
        if choice in ("3", "5"):
            fz.fuzz_headers()
        if choice in ("4", "5"):
            fz.fuzz_json()

    # ── Validate ─────────────────────────────────────────────────────────────
    def _menu_validate(self):
        from modules.validator import Validator
        v = Validator(self.s)
        v.validate_all()

    # ── Integrations ─────────────────────────────────────────────────────────
    def _menu_integrations(self):
        from integrations.runner import IntegrationRunner
        runner = IntegrationRunner(self.s)
        print(C.section("INTEGRATIONS"))
        tools = [
            ("1",  "nmap",         lambda: runner.run_nmap()),
            ("2",  "masscan",      lambda: runner.run_masscan()),
            ("3",  "amass",        lambda: runner.run_amass()),
            ("4",  "subfinder",    lambda: runner.run_subfinder()),
            ("5",  "httpx",        lambda: runner.run_httpx()),
            ("6",  "gau",          lambda: runner.run_gau()),
            ("7",  "waybackurls",  lambda: runner.run_waybackurls()),
            ("8",  "ffuf",         lambda: runner.run_ffuf()),
            ("9",  "dirsearch",    lambda: runner.run_dirsearch()),
            ("10", "linkfinder",   lambda: runner.run_linkfinder()),
            ("11", "arjun",        lambda: runner.run_arjun()),
            ("12", "nuclei",       lambda: runner.run_nuclei()),
            ("13", "dalfox",       lambda: runner.run_dalfox()),
            ("14", "sqlmap",       lambda: runner.run_sqlmap()),
            ("15", "jaeles",       lambda: runner.run_jaeles()),
            ("16", "403bypasser",  lambda: runner.run_403bypasser()),
            ("17", "keyleak",      lambda: runner.run_keyleak()),
            ("18", "wappalyzer",   lambda: runner.run_wappalyzer()),
            ("19", "shodan",       lambda: runner.run_shodan()),
            ("20", "google-dork",  lambda: runner.run_google_dork()),
            ("0",  "All OSS tools (1-20)", None),
        ]
        for key, label, _ in tools:
            print(f"  {C.BOLD}[{key:>2}]{C.RESET} {label}")
        choice = input("[?] Select: ").strip()
        for key, label, fn in tools:
            if choice == "0":
                if fn is not None:
                    fn()
            elif choice == key and fn is not None:
                fn()
                break

    # ── Report ───────────────────────────────────────────────────────────────
    def _menu_report(self):
        from reports.generator import ReportGenerator
        gen = ReportGenerator(self.s)
        print(C.section("REPORT"))
        print(f"  {C.BOLD}[1]{C.RESET} Markdown (.md)")
        print(f"  {C.BOLD}[2]{C.RESET} JSON (.json)")
        choice = input("[?] Select format: ").strip()
        fmt = {"1": "md", "2": "json"}.get(choice, "md")
        gen.generate(fmt=fmt)
