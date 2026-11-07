#!/usr/bin/env python3
"""
BBRecon - Bug Bounty Recon & Testing Framework
"""
import argparse
import sys
from pathlib import Path
from core.session import Session
from core.banner import print_banner
from core.menu import InteractiveMenu


def _run_pipeline(session, args) -> None:
    """Run the full automated pipeline: subdomains → dns → probe → crawl → js → aggregate → params → vuln → fuzz → validate → report."""
    from core.banner import C
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

    print(C.section("FULL PIPELINE"))
    print(C.info(f"Target: {session.target}\n"))

    # 1. Subdomain discovery
    recon = ReconModule(session)
    recon.enumerate_subdomains()
    recon.detect_technologies()
    recon.analyze_headers()

    # 2. DNS resolution
    dns = DNSResolver(session)
    dns.resolve_all()

    # 3. HTTP probing
    probe = HttpProbe(session)
    probe.probe_all()
    alive_urls = probe.get_alive_urls()

    # 4. Web crawling
    crawler = Crawler(session, max_depth=args.crawl_depth, max_pages=args.crawl_max)
    for url in alive_urls[:5]:  # Crawl top 5 alive hosts
        crawler.crawl(url)

    # 5. JavaScript analysis
    js = JSAnalyzer(session)
    js.analyze(list(crawler.js_urls))
    session.js_files = list(crawler.js_urls)

    # 6. Endpoint aggregation
    agg = EndpointAggregator(session)
    agg.aggregate(crawler=crawler, js_analyzer=js)

    # 7. Parameter discovery
    pd = ParamDiscovery(session)
    parameterized = agg.get_parameterized_urls()
    pd.discover(parameterized[:10])
    session.parameters = pd.discovered

    # 8. Vulnerability scanning
    vuln = VulnModule(session)
    test_urls = parameterized[:5] or [session.target]
    for url in test_urls:
        vuln.test_xss(url)
        vuln.test_sqli(url)
        vuln.test_ssrf(url)
        vuln.test_lfi(url)
        vuln.test_open_redirect(url)
    vuln.test_idor()

    # 9. Fuzzing
    fuzzer = Fuzzer(session)
    fuzzer.fuzz_paths()
    for url in test_urls[:3]:
        fuzzer.fuzz_params(url)
    fuzzer.fuzz_headers()

    # 10. Finding validation
    validator = Validator(session)
    validator.validate_all()

    # 11. Report
    gen = ReportGenerator(session)
    gen.generate(fmt=args.report_format)


def _run_against(target: str, args) -> None:
    """Run the requested command against a single target."""
    session = Session(target=target, output_dir=args.output, verbose=args.verbose)

    if args.command == "pipeline":
        _run_pipeline(session, args)
        session.save()
        return

    if args.command == "recon":
        from modules.recon import ReconModule
        mod = ReconModule(session)
        if args.all or args.subdomains:
            mod.enumerate_subdomains()
        if args.all or args.ports:
            mod.port_scan()
        if args.all or args.tech:
            mod.detect_technologies()
        if args.all or args.headers:
            mod.analyze_headers()
        if args.all or getattr(args, "dns", False):
            from modules.dns_resolver import DNSResolver
            DNSResolver(session).resolve_all()
        if args.all or getattr(args, "probe", False):
            from modules.http_probe import HttpProbe
            HttpProbe(session).probe_all()

    elif args.command == "discover":
        from modules.crawler import Crawler
        from modules.js_analyzer import JSAnalyzer
        from modules.endpoint_aggregator import EndpointAggregator
        from modules.param_discovery import ParamDiscovery

        if args.all or args.crawl:
            c = Crawler(session, max_depth=args.crawl_depth, max_pages=args.crawl_max)
            c.crawl()
            session.js_files = list(c.js_urls)
            session.forms = c.forms_found
            if args.all or args.js:
                js = JSAnalyzer(session)
                js.analyze(list(c.js_urls))
        elif args.js:
            js = JSAnalyzer(session)
            js.analyze(session.js_files)

        if args.all or args.aggregate:
            agg = EndpointAggregator(session)
            agg.aggregate()

        if args.all or args.params:
            pd = ParamDiscovery(session)
            pd.discover()
            session.parameters = pd.discovered

    elif args.command == "vuln":
        from modules.vuln import VulnModule
        mod = VulnModule(session)
        if args.all or args.xss:
            mod.test_xss()
        if args.all or args.sqli:
            mod.test_sqli()
        if args.all or args.ssrf:
            mod.test_ssrf()
        if args.all or args.idor:
            mod.test_idor()
        if args.all or args.lfi:
            mod.test_lfi()
        if args.all or getattr(args, "redirect", False):
            mod.test_open_redirect()

    elif args.command == "fuzz":
        from modules.fuzzer import Fuzzer
        fz = Fuzzer(session)
        if args.all or args.paths:
            fz.fuzz_paths()
        if args.all or args.fuzz_params:
            fz.fuzz_params()
        if args.all or args.fuzz_headers:
            fz.fuzz_headers()
        if args.json_body:
            import json
            try:
                body = json.loads(args.json_body)
            except json.JSONDecodeError:
                print("Error: --json-body must be valid JSON")
                body = None
            if body:
                fz.fuzz_json(base_body=body)

    elif args.command == "validate":
        from modules.validator import Validator
        Validator(session).validate_all()

    elif args.command == "integrations":
        from integrations.runner import IntegrationRunner
        runner = IntegrationRunner(session)
        run_all = args.all

        if run_all or args.nmap:            runner.run_nmap()
        if run_all or args.masscan:         runner.run_masscan(ports=args.masscan_ports, rate=args.masscan_rate)
        if run_all or args.amass:           runner.run_amass()
        if run_all or args.subfinder:       runner.run_subfinder()
        if run_all or args.massdns:         runner.run_massdns(wordlist=args.wordlist, resolvers=args.resolvers)
        if run_all or args.httpx:           runner.run_httpx()
        if run_all or args.shodan:          runner.run_shodan(api_key=args.shodan_key)
        if run_all or args.gau:             runner.run_gau()
        if run_all or args.waybackurls:     runner.run_waybackurls()
        if run_all or args.ffuf:            runner.run_ffuf(wordlist=args.wordlist)
        if run_all or args.dirsearch:       runner.run_dirsearch(wordlist=args.wordlist)
        if run_all or args.linkfinder:      runner.run_linkfinder()
        if run_all or args.arjun:           runner.run_arjun()
        if run_all or args.wappalyzer:      runner.run_wappalyzer()
        if run_all or args.google_dork:     runner.run_google_dork(api_key=args.google_key, cx=args.google_cx)
        if run_all or args.nuclei:          runner.run_nuclei(templates=args.templates)
        if run_all or args.dalfox:          runner.run_dalfox()
        if run_all or args.sqlmap:          runner.run_sqlmap(level=args.sqlmap_level, risk=args.sqlmap_risk)
        if run_all or args.jaeles:          runner.run_jaeles(signatures=args.jaeles_sigs)
        if run_all or args.bypasser403:     runner.run_403bypasser()
        if run_all or args.keye:            runner.run_keye()
        if run_all or args.keyleak:         runner.run_keyleak()
        if args.burpsuite:                  runner.run_burpsuite(base_url=args.burp_url, api_key=args.burp_key)
        if args.acunetix:                   runner.run_acunetix(base_url=args.acunetix_url, api_key=args.acunetix_key)
        if args.nessus:                     runner.run_nessus(base_url=args.nessus_url, access_key=args.nessus_access_key, secret_key=args.nessus_secret_key)

    elif args.command == "report":
        from reports.generator import ReportGenerator
        gen = ReportGenerator(session)
        gen.generate(fmt=args.format)

    session.save()


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="BBRecon - Bug Bounty Recon & Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  pipeline      Full automated pipeline (recommended for first run)
  recon         Subdomain enum, DNS resolution, HTTP probing, tech detection
  discover      Crawling, JS analysis, endpoint aggregation, param discovery
  vuln          Vulnerability testing (XSS, SQLi, SSRF, IDOR, LFI, Open Redirect)
  fuzz          Fuzzing engine (paths, params, headers, JSON bodies)
  validate      Re-verify findings to eliminate false positives
  integrations  27+ external tool integrations
  report        Generate findings report (Markdown/JSON)

Examples:
  python main.py -t example.com                              # Interactive mode
  python main.py -t example.com pipeline                     # Full automated scan
  python main.py -t example.com recon --all                  # Full recon
  python main.py -t example.com discover --all               # Crawl + JS + params
  python main.py -t example.com vuln --all                   # All vuln tests
  python main.py -t example.com fuzz --all                   # All fuzzing
  python main.py -t example.com validate                     # Verify findings
  python main.py --scope targets.txt pipeline                # Multi-target pipeline
        """
    )

    parser.add_argument("-t", "--target", help="Target domain or URL")
    parser.add_argument("-o", "--output", help="Output directory", default="./output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--scope", help="Scope file — one domain/URL per line")
    parser.add_argument("--rate", type=float, default=10.0, help="Requests/sec rate limit (default: 10)")

    subparsers = parser.add_subparsers(dest="command")

    # ── Pipeline (full auto) ──────────────────────────────────────────────────
    pipe_p = subparsers.add_parser("pipeline", help="Full automated recon-to-report pipeline")
    pipe_p.add_argument("--crawl-depth",   type=int, default=3,  dest="crawl_depth",  help="Crawler depth (default: 3)")
    pipe_p.add_argument("--crawl-max",     type=int, default=100,dest="crawl_max",    help="Max pages to crawl (default: 100)")
    pipe_p.add_argument("--report-format", default="md",         dest="report_format", choices=["md", "json"], help="Report format")

    # ── Recon ─────────────────────────────────────────────────────────────────
    recon_p = subparsers.add_parser("recon", help="Reconnaissance module")
    recon_p.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    recon_p.add_argument("--ports",      action="store_true", help="Port scanning")
    recon_p.add_argument("--tech",       action="store_true", help="Technology detection")
    recon_p.add_argument("--headers",    action="store_true", help="Analyze HTTP headers")
    recon_p.add_argument("--dns",        action="store_true", help="DNS resolution for subdomains")
    recon_p.add_argument("--probe",      action="store_true", help="HTTP probe alive hosts")
    recon_p.add_argument("--all",        action="store_true", help="Run all recon modules")

    # ── Discovery ─────────────────────────────────────────────────────────────
    disc_p = subparsers.add_parser("discover", help="Crawl, JS analysis, param discovery")
    disc_p.add_argument("--crawl",       action="store_true", help="Web crawler")
    disc_p.add_argument("--js",          action="store_true", help="JavaScript endpoint analysis")
    disc_p.add_argument("--aggregate",   action="store_true", help="Aggregate and deduplicate endpoints")
    disc_p.add_argument("--params",      action="store_true", help="Discover hidden parameters")
    disc_p.add_argument("--crawl-depth", type=int, default=3,   dest="crawl_depth", help="Crawler depth")
    disc_p.add_argument("--crawl-max",   type=int, default=100, dest="crawl_max",   help="Max pages")
    disc_p.add_argument("--all",         action="store_true", help="Run all discovery modules")

    # ── Vuln ──────────────────────────────────────────────────────────────────
    vuln_p = subparsers.add_parser("vuln", help="Vulnerability testing module")
    vuln_p.add_argument("--xss",      action="store_true", help="Test for XSS")
    vuln_p.add_argument("--sqli",     action="store_true", help="Test for SQL Injection")
    vuln_p.add_argument("--ssrf",     action="store_true", help="Test for SSRF")
    vuln_p.add_argument("--idor",     action="store_true", help="Test for IDOR patterns")
    vuln_p.add_argument("--lfi",      action="store_true", help="Test for LFI/Path Traversal")
    vuln_p.add_argument("--redirect", action="store_true", help="Test for Open Redirect")
    vuln_p.add_argument("--all",      action="store_true", help="Run all vuln tests")

    # ── Fuzz ──────────────────────────────────────────────────────────────────
    fuzz_p = subparsers.add_parser("fuzz", help="Fuzzing engine")
    fuzz_p.add_argument("--paths",        action="store_true", help="Fuzz URL paths")
    fuzz_p.add_argument("--fuzz-params",  action="store_true", dest="fuzz_params",   help="Fuzz query parameters")
    fuzz_p.add_argument("--fuzz-headers", action="store_true", dest="fuzz_headers",  help="Fuzz HTTP headers")
    fuzz_p.add_argument("--json-body",    dest="json_body",    help="JSON body to fuzz (e.g. '{\"id\":\"1\"}')")
    fuzz_p.add_argument("--all",          action="store_true", help="Run all fuzz modes")

    # ── Validate ──────────────────────────────────────────────────────────────
    subparsers.add_parser("validate", help="Re-verify findings to eliminate false positives")

    # ── Integrations ──────────────────────────────────────────────────────────
    int_p = subparsers.add_parser("integrations", help="External tools integration")
    int_p.add_argument("--nmap",         action="store_true")
    int_p.add_argument("--masscan",      action="store_true")
    int_p.add_argument("--amass",        action="store_true")
    int_p.add_argument("--subfinder",    action="store_true")
    int_p.add_argument("--massdns",      action="store_true")
    int_p.add_argument("--httpx",        action="store_true")
    int_p.add_argument("--shodan",       action="store_true")
    int_p.add_argument("--gau",          action="store_true")
    int_p.add_argument("--waybackurls",  action="store_true")
    int_p.add_argument("--ffuf",         action="store_true")
    int_p.add_argument("--dirsearch",    action="store_true")
    int_p.add_argument("--linkfinder",   action="store_true")
    int_p.add_argument("--arjun",        action="store_true")
    int_p.add_argument("--wappalyzer",   action="store_true")
    int_p.add_argument("--google-dork",  action="store_true", dest="google_dork")
    int_p.add_argument("--nuclei",       action="store_true")
    int_p.add_argument("--dalfox",       action="store_true")
    int_p.add_argument("--sqlmap",       action="store_true")
    int_p.add_argument("--jaeles",       action="store_true")
    int_p.add_argument("--403bypasser",  action="store_true", dest="bypasser403")
    int_p.add_argument("--keye",         action="store_true")
    int_p.add_argument("--keyleak",      action="store_true")
    int_p.add_argument("--burpsuite",    action="store_true")
    int_p.add_argument("--acunetix",     action="store_true")
    int_p.add_argument("--nessus",       action="store_true")
    int_p.add_argument("--all",          action="store_true")
    int_p.add_argument("--wordlist")
    int_p.add_argument("--templates")
    int_p.add_argument("--resolvers")
    int_p.add_argument("--jaeles-sigs",   dest="jaeles_sigs")
    int_p.add_argument("--masscan-ports", default="0-65535",  dest="masscan_ports")
    int_p.add_argument("--masscan-rate",  type=int, default=10000, dest="masscan_rate")
    int_p.add_argument("--sqlmap-level",  type=int, default=1, choices=range(1,6), dest="sqlmap_level")
    int_p.add_argument("--sqlmap-risk",   type=int, default=1, choices=range(1,4), dest="sqlmap_risk")
    int_p.add_argument("--shodan-key",        dest="shodan_key")
    int_p.add_argument("--google-key",        dest="google_key")
    int_p.add_argument("--google-cx",         dest="google_cx")
    int_p.add_argument("--burp-url",          dest="burp_url")
    int_p.add_argument("--burp-key",          dest="burp_key")
    int_p.add_argument("--acunetix-url",      dest="acunetix_url")
    int_p.add_argument("--acunetix-key",      dest="acunetix_key")
    int_p.add_argument("--nessus-url",        dest="nessus_url")
    int_p.add_argument("--nessus-access-key", dest="nessus_access_key")
    int_p.add_argument("--nessus-secret-key", dest="nessus_secret_key")

    # ── Report ────────────────────────────────────────────────────────────────
    report_p = subparsers.add_parser("report", help="Generate report")
    report_p.add_argument("--format", choices=["json", "md"], default="md")

    args = parser.parse_args()

    # Apply global rate limit
    if hasattr(args, "rate"):
        from core.rate_limiter import RateLimiter
        from core import http_client
        http_client.set_limiter(RateLimiter(requests_per_second=args.rate))

    # ── Interactive mode
    if not args.command:
        target = args.target or input("\n[?] Target domain/URL: ").strip()
        session = Session(target=target, output_dir=args.output, verbose=args.verbose)
        menu = InteractiveMenu(session)
        menu.run()
        return

    # ── Resolve targets
    targets = []
    if args.scope:
        scope_file = Path(args.scope)
        if not scope_file.exists():
            parser.error(f"Scope file not found: {args.scope}")
        for line in scope_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
        if not targets:
            parser.error(f"Scope file '{args.scope}' is empty")
        print(f"[*] Loaded {len(targets)} targets from: {args.scope}\n")

    if args.target:
        if args.target not in targets:
            targets.insert(0, args.target)

    if not targets:
        parser.error("Provide -t <target> or --scope <file>")

    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{'='*60}")
            print(f"  TARGET {i}/{len(targets)}: {target}")
            print(f"{'='*60}\n")
        _run_against(target, args)


if __name__ == "__main__":
    main()
