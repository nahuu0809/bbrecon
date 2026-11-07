# BugRecon AI Skills

This document helps Claude Code understand the capabilities, architecture, and goals of the BugRecon project.

## Project Overview

BugRecon is a modular bug bounty reconnaissance and vulnerability scanning framework written in Python using only the standard library.

It is designed for:

- Reconnaissance
- Vulnerability discovery
- Bug bounty automation
- Integration with external security tools

The framework targets **authorized bug bounty programs only**.

Primary goals:

1. Discover attack surface
2. Detect common web vulnerabilities
3. Integrate external scanners
4. Generate bug bounty ready reports

---

# Core Capabilities

## Recon

The recon module performs attack surface discovery.

Features:

- Subdomain brute forcing
- Port scanning
- Technology detection
- Security header analysis

Files:

modules/recon.py

Key functions:

- enumerate_subdomains()
- port_scan()
- detect_technologies()
- analyze_headers()

---

## Vulnerability Scanning

The vuln module tests common web vulnerabilities.

Files:

modules/vuln.py

Current tests:

- XSS
- SQL Injection
- SSRF
- IDOR

Future tests planned:

- LFI
- Open Redirect
- SSTI
- CSRF
- JWT misconfigurations

---

## Integrations

External tools supported:

- nmap
- ffuf
- nuclei

File:

integrations/runner.py

Purpose:

- run external scanners
- capture output
- convert results into findings

---

## Reporting

Reports can be generated in:

- Markdown
- JSON
- Text

File:

generator.py

Future improvements:

- HackerOne formatted reports
- CVSS scoring
- vulnerability severity ranking

---

## Session Management

All data is stored in the Session object.

File:

core/session.py

Session tracks:

- target
- start time
- discovered subdomains
- URLs
- findings
- vulnerabilities

---

# Architecture

High level structure:

main.py

    CLI parser
    │
    ├── ReconModule
    ├── VulnModule
    ├── IntegrationRunner
    └── ReportGenerator

---

# Design Philosophy

BugRecon follows these principles:

- minimal dependencies
- modular architecture
- bug bounty focused
- easily extensible
- automation friendly

---

# Intended AI Usage

AI agents (Claude Code, Codex, etc.) should:

- add new recon modules
- add new vulnerability checks
- improve payload generation
- implement better crawling
- integrate new security tools

---

# Important Bug Bounty Rules

The framework must respect:

- scope restrictions
- rate limits
- safe testing practices

See:

rules_bug_bounty.md

---

# Future Vision

BugRecon should evolve into:

a full bug bounty automation platform capable of:

- asset discovery
- attack surface mapping
- automated fuzzing
- vulnerability validation
- automatic report generation