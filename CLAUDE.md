# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**BBRecon** is an automated bug bounty reconnaissance and vulnerability discovery platform. Pure Python 3.10+, zero external pip dependencies (stdlib only). Optional integrations with 20+ external security tools.

## Running the Tool

```bash
# Full automated pipeline
python main.py -t example.com pipeline

# Interactive mode (menu-driven)
python main.py -t example.com

# Individual stages
python main.py -t target.com recon --all --dns --probe
python main.py -t target.com discover --crawl --js --aggregate --params
python main.py -t target.com vuln --all --redirect
python main.py -t target.com fuzz --paths --params --headers --json
python main.py -t target.com validate
python main.py -t target.com report --format md

# Multi-target via scope file
python main.py -t target.com --scope targets.txt pipeline

# Rate limiting
python main.py -t target.com --rate 5 pipeline

# Integrations
python main.py -t target.com integrations --all
python main.py -t target.com integrations --sqlmap --sqlmap-level 3
```

No build step, no package installation needed. There is no test suite.

## Architecture

Package-based layout with a central `Session` object (core/session.py) as shared state passed to all modules. The `Finding` class has severity levels: critical, high, medium, low, info.

### Pipeline (executed by `pipeline` command)
```
subdomains → DNS resolve → HTTP probe → crawl → JS analysis → endpoint aggregation → param discovery → vuln scan → fuzz → validate → report
```

### Package structure
```
main.py                          CLI entry, argparse, pipeline orchestration
core/
  banner.py                      ANSI colors (C class), ASCII art banner
  session.py                     Session + Finding; saved to output/<target>/session.json
  menu.py                        Interactive menu (all stages accessible)
  rate_limiter.py                Token-bucket rate limiter with per-host adaptive backoff
  http_client.py                 Shared HTTP client (auto rate-limit, 429 handling)
modules/
  recon.py                       Subdomain enum, port scan, tech detection, header analysis
  dns_resolver.py                DNS resolution, wildcard detection, shared hosting flags
  http_probe.py                  Probes hosts on [443,80,8080,8443], tech from headers
  crawler.py                     BFS web crawler (depth/page limits, scope enforcement)
  js_analyzer.py                 JS source analysis: endpoints, secrets, parameters
  endpoint_aggregator.py         Collects/normalizes URLs from all sources
  param_discovery.py             Parameter brute-force + interesting param classification
  vuln.py                        XSS, SQLi, SSRF, IDOR, LFI, Open Redirect testing
  fuzzer.py                      Path/param/header/JSON body fuzzing with baseline comparison
  validator.py                   Finding verification with per-vuln-type confidence scoring
integrations/
  runner.py                      20+ external tool integrations (see below)
reports/
  generator.py                   Markdown + JSON reports with impact descriptions and PoC
```

### External tool integrations (integrations/runner.py)

| Group | Tools |
|---|---|
| Recon / enumeration | nmap, masscan, amass, subfinder, massdns, httpx, shodan |
| URL / content discovery | gau, waybackurls, ffuf, dirsearch, linkfinder, arjun, wappalyzer, google_dork |
| Vulnerability scanners | nuclei, dalfox, sqlmap, jaeles, 403bypasser, keye |
| Secret detection | keyleak (external + built-in `_keyleak_regex_scan` fallback) |
| Commercial (API) | burpsuite, acunetix, nessus (excluded from `--all`) |

## Key Conventions

- **HTTP requests** go through `core.http_client` which enforces rate limiting via `core.rate_limiter`. Automatic 429 backoff. User-Agent: `"Mozilla/5.0 BBRecon/1.0"`.
- **Concurrency** uses `concurrent.futures.ThreadPoolExecutor`.
- **Findings** are added via `session.add_finding(Finding(...))`.
- **Console output** uses ANSI color codes via `core.banner.C`. Keep this pattern.
- **Detection logic** is payload reflection + regex-based. New vuln types should follow existing patterns in `modules/vuln.py` and `modules/fuzzer.py`.
- **Validation** re-tests findings and assigns confidence scores (0.0–1.0). Unconfirmed findings are stripped from the session.
- **External tool output** is parsed from XML (nmap) or JSON (ffuf, nuclei). Tool availability is checked before invoking.
- Output written to `./output/<target>/` at runtime.
