#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys

from core.animations import HackerUI, ProgressBar
from core.logger import log_error, log_info, log_success, log_warning


# ------- GOODS-DRAGON Banner -------
def show_banner():
    banner = r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║    ██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗    ║
    ║    ██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔═══██╗████╗  ██║    ║
    ║    ██║  ██║██████╔╝███████║██║   ██║██║   ██║██╔██╗ ██║    ║
    ║    ██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║    ║
    ║    ██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║    ║
    ║    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝    ║
    ║                                                               ║
    ║                   🐉 GOODS-DRAGON v2.0.0 🐉                    ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print(f"{'='*50}")
    print(f"    Author : zeus (z4)")
    print(f"    Owner  : 0xL-DRAGON")
    print(f"    Repo   : github.com/0xL-DRAGON/GOODS-DRAGON")
    print(f"    Telegram : @iM_z4")
    print(f"{'='*50}\n")


# ------- Professional Graphical Menu -------


# ------- Main Entry -------
def main():
    import os
    os.makedirs("reports", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    # Ensure required directories exist
    import os
    os.makedirs("reports", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    # Check for --update before anything else
    if "--version" in sys.argv or "-V" in sys.argv:
        show_banner()
        sys.exit(0)

    if "--security-check" in sys.argv:
        print("\n🔍 GOODS-DRAGON Security Audit\n")
        import os, glob
        issues = 0
        
        # Check for sensitive files
        sensitive_patterns = ["*.log", "*.token", "*.key", "*.pem", "*.password", "*.secret", "*.env", "credentials.*", "auth.*", "private.*"]
        for pattern in sensitive_patterns:
            for f in glob.glob(f"**/{pattern}", recursive=True):
                if not any(x in f for x in [".git/", "__pycache__", "payloads/"]):
                    print(f"⚠️  Sensitive file found: {f}")
                    issues += 1
        
        # Check for tokens in files
        token_patterns_list = ["github_pat_", "pypi-", "sk-", "xoxb-", "xoxp-", "xoxr-", "xoxa-"]
        for f in glob.glob("**/*", recursive=True):
            if os.path.isfile(f) and not any(x in f for x in [".git/", "__pycache__", "payloads/"]):
                try:
                    with open(f, "r", errors="ignore") as fp:
                        content_f = fp.read()
                    for tp in token_patterns:
                        if tp in content_f:
                            print(f"🔴 TOKEN FOUND in: {f}")
                            issues += 1
                            break
                except:
                    pass
        
        # Check .gitignore exists
        if not os.path.exists(".gitignore"):
            print("❌ .gitignore is missing!")
            issues += 1
        else:
            with open(".gitignore") as f:
                gitignore_content = f.read()
            if "reports/" not in gitignore_content or "logs/" not in gitignore_content:
                print("⚠️  .gitignore may not be complete")
                issues += 1
        
        # Check pre-commit hook
        if os.path.exists(".git/hooks/pre-commit"):
            print("✅ Pre-commit security hook is active")
        else:
            print("❌ Pre-commit security hook is missing")
            issues += 1
        
        if issues == 0:
            print("\n✅ All security checks passed! Your project is clean.\n")
        else:
            print(f"\n❌ Found {issues} security issues. Please fix them.\n")
        sys.exit(0)

    if "--update" in sys.argv:
        from modules.core.updater import SelfUpdater

        log_info("=== Starting Self-Updater ===")
        updater = SelfUpdater()
        updater.run()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="GOODS-DRAGON - Advanced Pentesting & Bug Bounty Tool (Created by zeus @iM_z4)",
        epilog="For more info, contact @iM_z4 on Telegram",
    )

    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Control color output (default: auto)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ----- Subcommand: recon -----
    recon_parser = subparsers.add_parser(
        "recon",
        help="Reconnaissance: Subdomains, Wayback, Active Scan, Takeover, Cloud Enum, Public Info, Phone Info, Auto-Scan, Shodan, Censys, Cloud Scanner, OSINT, Email Harvest, AD Enum, Social Eng, Threat Intel, Dark Web, Payload Manager",
    )
    recon_parser.add_argument(
        "-t",
        "--target",
        required=False,
        help="Target domain (e.g. example.com) or IP or country code or phone number",
    )
    recon_parser.add_argument(
        "-w", "--wordlist", default="wordlists/subdomains.txt", help="Wordlist path"
    )
    recon_parser.add_argument(
        "--wayback",
        action="store_true",
        help="Fetch historical URLs from Wayback Machine",
    )
    recon_parser.add_argument(
        "--active-scan",
        action="store_true",
        help="Active subdomain scan with HTTP/HTTPS checks",
    )
    recon_parser.add_argument(
        "--takeover",
        action="store_true",
        help="Check for subdomain takeover vulnerabilities",
    )
    recon_parser.add_argument(
        "--cloud-enum",
        action="store_true",
        help="Enumerate cloud resources (AWS, Azure, GCP)",
    )
    recon_parser.add_argument(
        "--public-info",
        action="store_true",
        help="Get public info (IP geolocation, country details, domain info)",
    )
    recon_parser.add_argument(
        "--phone-info",
        action="store_true",
        help="Get phone number information (country, operator, type)",
    )
    recon_parser.add_argument(
        "--auto", action="store_true", help="Run all modules automatically (full scan)"
    )
    recon_parser.add_argument(
        "--auto-output", default="reports/auto_scan.json", help="Auto-scan output file"
    )
    recon_parser.add_argument(
        "--shodan", action="store_true", help="Shodan integration"
    )
    recon_parser.add_argument("--shodan-key", help="Shodan API key")
    recon_parser.add_argument(
        "--censys", action="store_true", help="Censys integration"
    )
    recon_parser.add_argument("--censys-id", help="Censys API ID")
    recon_parser.add_argument("--censys-secret", help="Censys API secret")
    recon_parser.add_argument(
        "--cloud-scanner",
        action="store_true",
        help="Scan for cloud resources (AWS S3, GCP, Azure)",
    )
    recon_parser.add_argument(
        "--osint", action="store_true", help="OSINT: Email, Phone, Social Media search"
    )
    recon_parser.add_argument(
        "--email-harvest",
        action="store_true",
        help="Harvest emails from Google, GitHub, and web",
    )
    recon_parser.add_argument(
        "--cloud-exploit",
        action="store_true",
        help="Check AWS S3, GCP, Azure for open buckets",
    )
    recon_parser.add_argument(
        "--ad-enum",
        action="store_true",
        help="Active Directory enumeration (DC, users, shares)",
    )
    recon_parser.add_argument(
        "--takeover-advanced",
        action="store_true",
        help="Advanced subdomain takeover check",
    )
    recon_parser.add_argument(
        "--social-eng",
        action="store_true",
        help="Social engineering: phishing links, leaked emails",
    )
    recon_parser.add_argument(
        "--threat-intel",
        action="store_true",
        help="Threat intelligence from VirusTotal, Shodan, AbuseIPDB",
    )
    recon_parser.add_argument(
        "--threat-intel-key",
        help="Comma-separated API keys: virustotal,shodan,abuseipdb",
    )
    recon_parser.add_argument(
        "--dark-web", action="store_true", help="Dark web monitoring for leaked data"
    )
    recon_parser.add_argument(
        "--payload-manager", action="store_true", help="Manage payloads database"
    )
    recon_parser.add_argument(
        "--payload-update",
        action="store_true",
        help="Update payloads from remote repository",
    )
    recon_parser.add_argument(
        "--payload-export", help="Export payloads to file (json/csv/txt)"
    )
    recon_parser.add_argument("--payload-category", help="Filter payloads by category")
    recon_parser.add_argument("--payload-tag", help="Filter payloads by tag")
    recon_parser.add_argument("--payload-search", help="Search payloads by keyword")
    recon_parser.add_argument(
        "--payload-add", help="Add payload to database (category:value)"
    )
    recon_parser.add_argument("--payload-remove", help="Remove payload by ID")
    recon_parser.add_argument(
        "--h1-report", action="store_true", help="Generate HackerOne format report"
    )
    recon_parser.add_argument(
        "--report", action="store_true", help="Generate HTML report"
    )
    recon_parser.add_argument(
        "--report-all",
        action="store_true",
        help="Generate all report formats (HTML, PDF, DOCX, JSON, CSV)",
    )
    recon_parser.add_argument(
        "--advanced-report",
        action="store_true",
        help="Generate advanced HTML and PDF reports",
    )
    recon_parser.add_argument(
        "-th", "--threads", type=int, default=30, help="Number of threads"
    )
    recon_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed logs"
    )
    recon_parser.add_argument(
        "-o", "--output", default="reports/recon_output.json", help="Output file path"
    )

    # ----- Subcommand: web -----
    web_parser = subparsers.add_parser(
        "web",
        help="Web vulnerabilities: SQLi, XSS, CMS, CVE, Headers, JS, Tech, Git, WAF, IDOR, SSTI, SSRF, LFI, CORS, JWT, Open Redirect, GraphQL, Rate Limit, 2FA, Param Discovery, Blind XSS, Secret Scanner, Version Scanner, Broken Link, Proxy, Exploit, Nikto, Smart Fuzzing, Business Logic, Race Condition, Chained Attack, Static Analysis, Smart Scan, Advanced Auto, Stealth Mode, Stealth Pro, WAF Bypass, Browser Emulator, Auto Proxy, API Scanner, AI Scanner, RCE Scanner, Directory Traversal, API Key Scanner, JWT/OAuth, Mobile Security, Login Bypass, Dir Bruteforce",
    )
    web_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target URL (e.g. http://testphp.vulnweb.com)",
    )
    web_parser.add_argument(
        "--sqli", action="store_true", help="Enable SQL Injection scan"
    )
    web_parser.add_argument("--xss", action="store_true", help="Enable XSS scan")
    web_parser.add_argument(
        "--log-check",
        action="store_true",
        help="Check for sensitive files (.env, .git, logs)",
    )
    web_parser.add_argument(
        "--login-bypass", action="store_true", help="Test login form bypass"
    )
    web_parser.add_argument(
        "--dir-bruteforce",
        action="store_true",
        help="Bruteforce hidden directories and files",
    )
    web_parser.add_argument(
        "--cms-detect",
        action="store_true",
        help="Detect CMS (WordPress, Joomla, Drupal, etc.)",
    )
    web_parser.add_argument(
        "--cve-scan",
        action="store_true",
        help="Check for known CVEs in detected technologies",
    )
    web_parser.add_argument(
        "--js-deps",
        action="store_true",
        help="Scan for vulnerable JavaScript libraries",
    )
    web_parser.add_argument(
        "--tech-detect",
        action="store_true",
        help="Detect web technologies (servers, frameworks, languages)",
    )
    web_parser.add_argument(
        "--headers-check",
        action="store_true",
        help="Check security headers (CSP, HSTS, XFO, etc.)",
    )
    web_parser.add_argument(
        "--git-scan", action="store_true", help="Scan for exposed Git repositories"
    )
    web_parser.add_argument(
        "--waf-detect", action="store_true", help="Detect Web Application Firewalls"
    )
    web_parser.add_argument(
        "--idor-scan", action="store_true", help="Scan for IDOR vulnerabilities"
    )
    web_parser.add_argument(
        "--ssti-scan",
        action="store_true",
        help="Scan for Server-Side Template Injection",
    )
    web_parser.add_argument(
        "--ssrf-scan", action="store_true", help="Scan for Server-Side Request Forgery"
    )
    web_parser.add_argument(
        "--lfi-scan", action="store_true", help="Scan for Local/Remote File Inclusion"
    )
    web_parser.add_argument(
        "--cors-check", action="store_true", help="Check for CORS misconfigurations"
    )
    web_parser.add_argument(
        "--jwt-scan", action="store_true", help="Scan for JWT tokens"
    )
    web_parser.add_argument(
        "--open-redirect",
        action="store_true",
        help="Scan for Open Redirect vulnerabilities",
    )
    web_parser.add_argument(
        "--graphql-scan",
        action="store_true",
        help="Scan for GraphQL endpoints and vulnerabilities",
    )
    web_parser.add_argument(
        "--rate-limit",
        action="store_true",
        help="Check for rate limiting and bypass techniques",
    )
    web_parser.add_argument(
        "--2fa-bypass", action="store_true", help="Check for 2FA implementation"
    )
    web_parser.add_argument(
        "--param-discovery",
        action="store_true",
        help="Discover hidden parameters in URLs",
    )
    web_parser.add_argument(
        "--blind-xss", action="store_true", help="Test for Blind XSS vulnerabilities"
    )
    web_parser.add_argument(
        "--secret-scan",
        action="store_true",
        help="Scan for secrets, API keys, and tokens",
    )
    web_parser.add_argument(
        "--version-scan", action="store_true", help="Scan for software versions"
    )
    web_parser.add_argument(
        "--broken-link", action="store_true", help="Check for broken links"
    )
    web_parser.add_argument(
        "--fuzz", action="store_true", help="Smart fuzzing for new vulnerabilities"
    )
    web_parser.add_argument(
        "--fuzz-depth", type=int, default=100, help="Fuzzing depth per parameter"
    )
    web_parser.add_argument(
        "--business-logic", action="store_true", help="Check for business logic flaws"
    )
    web_parser.add_argument(
        "--race-condition", action="store_true", help="Detect race conditions"
    )
    web_parser.add_argument(
        "--chain-scan", action="store_true", help="Scan for chained attacks"
    )
    web_parser.add_argument(
        "--static-analysis", action="store_true", help="Static code analysis"
    )
    web_parser.add_argument(
        "--api-scanner",
        action="store_true",
        help="Scan for API vulnerabilities (Swagger, GraphQL, CORS)",
    )
    web_parser.add_argument(
        "--rce-scan",
        action="store_true",
        help="Remote Code Execution vulnerability scan",
    )
    web_parser.add_argument(
        "--dir-traversal",
        action="store_true",
        help="Test for directory traversal vulnerabilities",
    )
    web_parser.add_argument(
        "--api-key-scan",
        action="store_true",
        help="Scan for exposed API keys and tokens",
    )
    web_parser.add_argument(
        "--jwt-oauth", action="store_true", help="Test JWT tokens and OAuth endpoints"
    )
    web_parser.add_argument(
        "--mobile-security",
        action="store_true",
        help="Mobile security testing (API endpoints)",
    )
    web_parser.add_argument(
        "--stealth",
        action="store_true",
        help="Enable stealth mode (proxy, random User-Agent, delays)",
    )
    web_parser.add_argument(
        "--stealth-pro",
        action="store_true",
        help="Advanced stealth mode with cloudscraper and proxy rotation",
    )
    web_parser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Advanced WAF bypass with random headers, proxies, and delays",
    )
    web_parser.add_argument(
        "--browser-emulator",
        action="store_true",
        help="Full browser emulation with Selenium and JS execution",
    )
    web_parser.add_argument(
        "--headless",
        action="store_true",
        help="Run browser in headless mode (for --browser-emulator)",
    )
    web_parser.add_argument(
        "--auto-proxy",
        action="store_true",
        help="Enable automatic proxy rotation from public APIs",
    )
    web_parser.add_argument(
        "--proxy-interval",
        type=int,
        default=30,
        help="Proxy rotation interval in seconds",
    )
    web_parser.add_argument(
        "--ai-scan",
        action="store_true",
        help="AI-powered scanning with smart payload selection",
    )
    web_parser.add_argument(
        "--proxy-list",
        help="Comma-separated list of proxies (e.g. http://proxy1:8080,http://proxy2:8080)",
    )
    web_parser.add_argument(
        "--proxy", action="store_true", help="Start proxy server (Burp Suite style)"
    )
    web_parser.add_argument(
        "--proxy-port", type=int, default=8080, help="Proxy port (default: 8080)"
    )
    web_parser.add_argument(
        "--exploit", action="store_true", help="Run exploit module (Metasploit style)"
    )
    web_parser.add_argument(
        "--nikto", action="store_true", help="Run Nikto-style vulnerability scanner"
    )
    web_parser.add_argument("--smart-scan", action="store_true", help="Auto-detect rate limit")
    web_parser.add_argument("--chain-attack", action="store_true", help="Run Smart Compound Attack Engine")
    web_parser.add_argument("--auto-exploit", action="store_true", help="Auto-suggest exploits for detected technologies")
    web_parser.add_argument(
        "--auto-advanced",
        action="store_true",
        help="Advanced auto detection and smart scanning",
    )
    web_parser.add_argument(
        "--wordlist",
        default="wordlists/dirs.txt",
        help="Wordlist for directory bruteforce",
    )
    web_parser.add_argument(
        "--report", action="store_true", help="Generate HTML report"
    )
    web_parser.add_argument(
        "--report-pdf", action="store_true", help="Generate PDF report"
    )
    web_parser.add_argument(
        "--report-txt", action="store_true", help="Generate TXT report"
    )
    web_parser.add_argument(
        "-th", "--threads", type=int, default=30, help="Number of threads"
    )
    web_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed logs"
    )
    web_parser.add_argument(
        "-o", "--output", default="reports/web_output.json", help="Output file path"
    )

    # ----- Subcommand: scan -----
    scan_parser = subparsers.add_parser(
        "scan",
        help="Network scanning: Port Scanner, Host Discovery, S3, SSL, Brute Force, Password Cracking, Exploit Development",
    )
    scan_parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP, domain, or subnet (e.g. 192.168.1.0/24)",
    )
    scan_parser.add_argument(
        "-p",
        "--ports",
        default="21,22,23,25,80,443,3306,3389,8080",
        help="Port range (e.g. 1-1000 or 80,443)",
    )
    scan_parser.add_argument(
        "--ping-sweep",
        action="store_true",
        help="Discover alive hosts on the network (subnet required)",
    )
    scan_parser.add_argument(
        "--s3-find", action="store_true", help="Search for open S3 buckets"
    )
    scan_parser.add_argument(
        "--ssl-check", action="store_true", help="Check SSL/TLS certificate validity"
    )
    scan_parser.add_argument(
        "--bruteforce", action="store_true", help="Brute force SSH/FTP/RDP credentials"
    )
    scan_parser.add_argument(
        "--password-crack",
        action="store_true",
        help="Password cracking with dictionary",
    )
    scan_parser.add_argument(
        "--exploit-dev",
        action="store_true",
        help="Exploit development and PoC generation",
    )
    scan_parser.add_argument(
        "--service",
        choices=["ssh", "ftp", "rdp"],
        default="ssh",
        help="Service to brute force",
    )
    scan_parser.add_argument(
        "--userlist", default="root,admin", help="List of usernames (comma separated)"
    )
    scan_parser.add_argument(
        "--passlist",
        default="password,123456,admin",
        help="List of passwords (comma separated)",
    )
    scan_parser.add_argument(
        "--report", action="store_true", help="Generate HTML report"
    )
    scan_parser.add_argument(
        "-b", "--banner", action="store_true", help="Grab service banners"
    )
    scan_parser.add_argument(
        "-th", "--threads", type=int, default=50, help="Number of threads"
    )
    scan_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed logs"
    )
    scan_parser.add_argument(
        "-o", "--output", default="reports/scan_output.json", help="Output file path"
    )

    # ----- Subcommand: webui -----
    subparsers.add_parser("webui", help="Start the Web-based Control Panel")

    args = parser.parse_args()

    # Apply color setting
    from core.color_config import set_color_mode

    set_color_mode(args.color)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # ------- Execute recon -------
    if args.command == "webui":
        log_info("Starting Web Control Panel...")
        log_info("Open http://localhost:5000 in your browser")
        from webui import app

        app.run(host="0.0.0.0", port=5000, debug=False)
        sys.exit(0)

    if args.command == "recon":
        # ----- Payload Manager (no target needed) -----
        if args.payload_manager:
            from modules.core.payload_manager import PayloadManager

            log_info("=== Starting Payload Manager ===")
            manager = PayloadManager(verbose=args.verbose)

            if args.payload_update:
                log_info("Updating payloads from remote repository...")
                manager.update_from_remote()
                sys.exit(0)

            if args.payload_export:
                log_info(f"Exporting payloads to: {args.payload_export}")
                manager.export_payloads(args.payload_export)
                sys.exit(0)

            if args.payload_search:
                log_info(f"Searching for: {args.payload_search}")
                results = manager.search_payloads(args.payload_search)
                log_info(f"Found {len(results)} results:")
                for r in results[:20]:
                    log_info(
                        f"  [{r.get('category', 'unknown')}] {r.get('id')}: {r.get('value', '')[:50]}..."
                    )
                sys.exit(0)

            if args.payload_add:
                if ":" in args.payload_add:
                    category, value = args.payload_add.split(":", 1)
                    payload = {
                        "value": value,
                        "type": "custom",
                        "tags": ["user_added"],
                        "severity": "medium",
                    }
                    manager.add_payload(category.strip(), payload)
                sys.exit(0)

            if args.payload_remove:
                for category in manager.payloads.keys():
                    if manager.remove_payload(category, args.payload_remove):
                        break
                sys.exit(0)

            results = manager.run()
            stats = results.get("stats", {})
            log_info("=== Payload Database Statistics ===")
            log_info(f"Version: {stats.get('version', 'unknown')}")
            log_info(f"Last Updated: {stats.get('last_updated', 'never')}")
            log_info(f"Total Payloads: {stats.get('total_payloads', 0)}")
            log_info(f"Categories: {stats.get('categories', 0)}")
            log_info("  Category Breakdown:")
            for cat, count in stats.get("category_breakdown", {}).items():
                log_info(f"    {cat}: {count}")
            sys.exit(0)

        # ----- All other recon modules require target -----
        if not args.target:
            parser.error(
                "the following arguments are required for recon: -t/--target (unless using --payload-manager)"
            )

        # ----- Cloud Scanner -----
        if args.cloud_scanner:
            from modules.recon.cloud_scanner import CloudScanner

            log_info("=== Starting Cloud Scanner ===")
            scanner = CloudScanner(args.target, args.verbose)
            results = scanner.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Cloud Scanner completed.")
            sys.exit(0)

        # ----- OSINT -----
        if args.osint:
            from modules.recon.osint import OSINT

            log_info("=== Starting OSINT ===")
            osint = OSINT(args.target, args.verbose)
            results = osint.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - OSINT completed.")
            sys.exit(0)

        # ----- Email Harvest -----
        if args.email_harvest:
            from modules.recon.email_harvester import EmailHarvester

            log_info("=== Starting Email Harvest ===")
            harvest = EmailHarvester(args.target, args.verbose)
            results = harvest.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Email Harvest completed.")
            sys.exit(0)

        # ----- AD Enum -----
        if args.ad_enum:
            from modules.recon.ad_enum import ADEnum

            log_info("=== Starting AD Enum ===")
            ad = ADEnum(args.target, args.verbose)
            results = ad.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - AD Enum completed.")
            sys.exit(0)

        # ----- Social Engineering -----
        if args.social_eng:
            from modules.recon.social_eng import SocialEngineering

            log_info("=== Starting Social Engineering ===")
            social = SocialEngineering(args.target, args.verbose)
            results = social.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Social Engineering completed.")
            sys.exit(0)

        # ----- Threat Intelligence -----
        if args.threat_intel:
            from modules.recon.threat_intel import ThreatIntel

            log_info("=== Starting Threat Intelligence ===")
            api_keys = {}
            if args.threat_intel_key:
                keys = args.threat_intel_key.split(",")
                for key in keys:
                    if "=" in key:
                        k, v = key.split("=", 1)
                        api_keys[k.strip()] = v.strip()
            threat = ThreatIntel(args.target, args.verbose, api_keys)
            results = threat.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Threat Intelligence completed.")
            sys.exit(0)

        # ----- Dark Web -----
        if args.dark_web:
            from modules.recon.dark_web import DarkWebMonitor

            log_info("=== Starting Dark Web Monitoring ===")
            dark = DarkWebMonitor(args.target, args.verbose)
            results = dark.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Dark Web completed.")
            sys.exit(0)

        # ----- Advanced Report -----
        if args.advanced_report:
            from modules.reporting.advanced_report import AdvancedReport

            log_info("=== Generating Advanced Report ===")
            report = AdvancedReport(args.output)
            report.generate_all()
            log_success("Advanced report generated successfully!")
            sys.exit(0)

        # ----- Auto-Scanner -----
        if args.auto:
            from modules.web.auto_scanner import AutoScanner

            log_info("=== Starting Auto-Scanner ===")
            scanner = AutoScanner(
                target=args.target,
                verbose=args.verbose,
                threads=args.threads,
                output=args.auto_output,
            )
            results = scanner.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Auto-scan results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Auto-scan completed.")
            sys.exit(0)

        # ----- Dynamic Report -----
        if args.report_all:
            from modules.reporting.dynamic_report import DynamicReport

            log_info("=== Generating All Reports ===")
            report = DynamicReport(args.output)
            report.generate_all()
            log_success("All reports generated successfully!")
            sys.exit(0)

        # ----- HackerOne Report -----
        if args.h1_report:
            from modules.reporting.hackerone_format import HackerOneReport

            log_info("=== Generating HackerOne Report ===")
            report = HackerOneReport(args.output, "hackerone_report.md")
            report.generate()
            log_info("GOODS-DRAGON - HackerOne Report completed.")
            sys.exit(0)

        # ----- Shodan Integration -----
        if args.shodan:
            from modules.recon.shodan import ShodanIntegration

            log_info("=== Starting Shodan Integration ===")
            shodan = ShodanIntegration(args.target, args.shodan_key, args.verbose)
            results = shodan.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Shodan Integration completed.")
            sys.exit(0)

        # ----- Censys Integration -----
        if args.censys:
            from modules.recon.censys import CensysIntegration

            log_info("=== Starting Censys Integration ===")
            censys = CensysIntegration(
                args.target, args.censys_id, args.censys_secret, args.verbose
            )
            results = censys.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Censys Integration completed.")
            sys.exit(0)

        # ----- Public Info -----
        if args.public_info:
            from modules.recon.public_info import PublicInfo

            log_info(f"GOODS-DRAGON - Public Info gathering on: {args.target}")
            pi = PublicInfo(args.target, args.verbose)
            results = pi.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Public Info completed.")
            sys.exit(0)

        # ----- Phone Info -----
        if args.phone_info:
            from modules.recon.phone_info import PhoneInfo

            log_info(f"GOODS-DRAGON - Phone Info gathering on: {args.target}")
            pi = PhoneInfo(args.target, args.verbose)
            results = pi.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport

                report_name = args.output.replace(".json", ".html")
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("GOODS-DRAGON - Phone Info completed.")
            sys.exit(0)

        from modules.recon.active_scan import ActiveSubdomainScanner
        from modules.recon.subdomain import SubdomainFinder
        from modules.recon.wayback import WaybackScanner

        HackerUI.scan_header(args.target, "Reconnaissance Scanner")
        log_info(f"GOODS-DRAGON - Recon started on: {args.target}")
        results = {}

        finder = SubdomainFinder(
            domain=args.target,
            wordlist_path=args.wordlist,
            threads=args.threads,
            verbose=args.verbose,
        )
        results["subdomains"] = finder.run()

        if args.wayback:
            log_info("=== Starting Wayback URL Fetch ===")
            wayback = WaybackScanner(args.target, args.verbose)
            results["wayback"] = wayback.run()

        if args.active_scan:
            log_info("=== Starting Active Subdomain Scan ===")
            active = ActiveSubdomainScanner(
                args.target, args.wordlist, args.threads, args.verbose
            )
            results["active_scan"] = active.run()

        if args.takeover:
            from modules.recon.takeover import SubdomainTakeover

            log_info("=== Starting Subdomain Takeover Check ===")
            sub_list = results.get("subdomains", {}).get("subdomains", [])
            if sub_list:
                sub_names = [
                    s.get("subdomain", "") for s in sub_list if s.get("subdomain")
                ]
                if sub_names:
                    takeover = SubdomainTakeover(sub_names, args.verbose)
                    results["takeover"] = takeover.run()
                else:
                    log_warning("No subdomains found to check for takeover.")
            else:
                log_warning(
                    "Run subdomain enumeration first (--takeover needs subdomain list)."
                )

        if args.cloud_enum:
            from modules.recon.cloud_enum import CloudEnum

            log_info("=== Starting Cloud Enumeration ===")
            cloud = CloudEnum(args.target, args.threads, args.verbose)
            results["cloud_enum"] = cloud.run()

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log_success(f"Results saved to {args.output}")

        if args.report:
            from modules.reporting.html_report import HTMLReport

            report_name = args.output.replace(".json", ".html")
            report = HTMLReport(args.output, report_name)
            report.generate()

        if hasattr(args, "report_pdf") and args.report_pdf:
            from modules.reporting.pdf_report import PDFReport

            PDFReport(args.output).generate()

        if hasattr(args, "report_txt") and args.report_txt:
            from modules.reporting.pdf_report import TXTReport

            TXTReport(args.output).generate()

        log_info("GOODS-DRAGON - Recon completed. Stay secure!")

    # ------- Execute web -------
    elif args.command == "web":
        from modules.core.ai_scanner import AIScanner
        from modules.core.browser_emulator import BrowserEmulator
        from modules.core.proxy_manager import ProxyManager
        from modules.core.stealth import StealthMode
        from modules.core.stealth_pro import StealthPro
        from modules.core.waf_bypass import WAFBypass
        from modules.exploit.exploit import ExploitModule
        from modules.web.api_key_scanner import APIKeyScanner
        from modules.web.api_scanner import APIScanner
        from modules.web.auto_advanced import AdvancedAuto
        from modules.web.auto_throttle import AutoThrottle
        from modules.web.broken_link import BrokenLinkChecker
        from modules.web.business_logic import BusinessLogicChecker
        from modules.web.chained_attack import ChainedAttackScanner
        from modules.web.cms import CMSDetector
        from modules.web.collaborator.blind_xss import BlindXSSCollaborator
        from modules.web.cors import CORSChecker
        from modules.web.cve_scan import CVEScanner
        from modules.web.dir_bruteforce import DirBruteforce
        from modules.web.dir_traversal import DirTraversal
        from modules.web.disclosure import InfoDisclosureScanner
        from modules.web.git_scan import GitScanner
        from modules.web.graphql import GraphQLScanner
        from modules.web.headers_check import SecurityHeadersChecker
        from modules.web.idor import IDORScanner
        from modules.web.js_deps import JSDependencyScanner
        from modules.web.jwt import JWTScanner
        from modules.web.jwt_oauth import JWTOAuthTester
        from modules.web.lfi import LFIScanner
        from modules.web.login_bypass import LoginBypassScanner
        from modules.web.mobile_security import MobileSecurity
        from modules.web.nikto_style import NiktoStyleScanner
        from modules.web.open_redirect import OpenRedirectScanner
        from modules.web.param_discovery import ParameterDiscovery
        from modules.web.proxy import ProxyServer
        from modules.web.race_condition import RaceConditionDetector
        from modules.web.rate_limit import RateLimitChecker
        from modules.web.rce_scanner import RCEScanner
        from modules.web.secret_scanner import SecretScanner
        from modules.web.smart_fuzzing import SmartFuzzing
        from modules.web.sqli import SQLiScanner
        from modules.web.ssrf import SSRFScanner
        from modules.web.ssti import SSTIScanner
        from modules.web.static_analysis import StaticAnalysis
        from modules.web.tech_detect import TechnologyDetector
        from modules.web.twofa_bypass import TwoFABypass
        from modules.web.version_scanner import VersionScanner
        from modules.web.waf_detect import WAFDetector
        from modules.web.xss import XSSScanner

        if args.proxy:
            log_info("=== Starting Proxy Server ===")
            proxy = ProxyServer(port=args.proxy_port, verbose=args.verbose)
            log_info("Press Ctrl+C to stop the proxy")
            try:
                proxy.run()
            except KeyboardInterrupt:
                log_info("Proxy stopped")
            sys.exit(0)

        if args.auto_proxy:
            log_info("=== Starting Auto Proxy Manager ===")
            proxy_manager = ProxyManager(
                verbose=args.verbose,
                auto_rotate=True,
                rotate_interval=args.proxy_interval,
            )
            results = proxy_manager.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Proxy Manager results saved to {args.output}")
            log_info("Proxy manager is running in background. Starting scan...")
            os.environ["HTTP_PROXY"] = proxy_manager.get_proxy() or ""
            os.environ["HTTPS_PROXY"] = os.environ["HTTP_PROXY"]

        if args.stealth_pro:
            log_info("=== Starting Stealth Pro Mode ===")
            proxy_list = args.proxy_list.split(",") if args.proxy_list else None
            stealth = StealthPro(
                args.target,
                args.verbose,
                proxy_list,
                rotate_ua=True,
                use_cloudscraper=True,
            )
            results = stealth.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Stealth Pro results saved to {args.output}")
            sys.exit(0)

        if args.stealth:
            proxy_list = args.proxy_list.split(",") if args.proxy_list else None
            stealth = StealthMode(args.target, args.verbose, proxy_list)
            results = stealth.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Stealth results saved to {args.output}")
            sys.exit(0)

        HackerUI.scan_header(args.target, "Web Vulnerability Scanner")
        log_info(f"GOODS-DRAGON - Web scanner started on: {args.target}")
        results = {}

        if args.log_check:
            log_info("=== Starting Info Disclosure Scan ===")
            disclosure = InfoDisclosureScanner(args.target, args.verbose)
            results["info_disclosure"] = disclosure.run()

        if args.sqli:
            pb = ProgressBar(100, prefix="SQLi Scanner", length=25)
            pb.start_animation()
            log_info("=== Starting SQL Injection Scan ===")
            sqli = SQLiScanner(args.target, args.verbose)
            pb.stop(True)
            results["sqli"] = sqli.run()

        if args.xss:
            pb = ProgressBar(100, prefix="XSS Scanner", length=25)
            pb.start_animation()
            log_info("=== Starting XSS Scan ===")
            xss = XSSScanner(args.target, args.verbose, args.threads)
            pb.stop(True)
            results["xss"] = xss.run()

        if args.login_bypass:
            log_info("=== Starting Login Bypass Scan ===")
            login = LoginBypassScanner(args.target, args.verbose)
            results["login_bypass"] = login.run()

        if args.dir_bruteforce:
            log_info("=== Starting Directory Bruteforce ===")
            dir_bf = DirBruteforce(
                target=args.target,
                wordlist_path=args.wordlist,
                threads=args.threads,
                verbose=args.verbose,
            )
            results["dir_bruteforce"] = dir_bf.run()

        if args.cms_detect:
            log_info("=== Starting CMS Detection ===")
            cms = CMSDetector(args.target, args.verbose)
            results["cms"] = cms.run()

        if args.tech_detect or (
            args.cve_scan and not args.tech_detect and not args.cms_detect
        ):
            if not args.tech_detect and args.cve_scan:
                log_info("Running Tech detection for CVE matching...")
            log_info("=== Starting Technology Detection ===")
            tech = TechnologyDetector(args.target, args.verbose)
            results["tech_detect"] = tech.run()
        elif args.tech_detect:
            log_info("=== Starting Technology Detection ===")
            tech = TechnologyDetector(args.target, args.verbose)
            results["tech_detect"] = tech.run()

        if args.cve_scan and not args.cms_detect:
            log_info("Running CMS detection for CVE matching...")
            cms = CMSDetector(args.target, args.verbose)
            results["cms"] = cms.run()

        if args.cve_scan:
            log_info("=== Starting CVE Vulnerability Scan ===")
            cve_scanner = CVEScanner(
                target=args.target,
                cms_data=results.get("cms", {}),
                tech_data=results.get("tech_detect", {}),
                verbose=args.verbose,
            )
            results["cve_scan"] = cve_scanner.run()

        if args.js_deps:
            log_info("=== Starting JS Dependency Scan ===")
            js = JSDependencyScanner(args.target, args.verbose)
            results["js_deps"] = js.run()

        if args.headers_check:
            pb = ProgressBar(100, prefix="Headers Check", length=25)
            pb.start_animation()
            log_info("=== Starting Security Headers Check ===")
            headers = SecurityHeadersChecker(args.target, args.verbose)
            pb.stop(True)
            results["headers_check"] = headers.run()

        if args.git_scan:
            log_info("=== Starting Git Repository Scan ===")
            git = GitScanner(args.target, args.verbose)
            results["git_scan"] = git.run()

        if args.waf_detect:
            log_info("=== Starting WAF Detection ===")
            waf = WAFDetector(args.target, args.verbose)
            results["waf_detect"] = waf.run()

        if args.idor_scan:
            log_info("=== Starting IDOR Scan ===")
            idor = IDORScanner(args.target, args.verbose)
            results["idor"] = idor.run()

        if args.ssti_scan:
            log_info("=== Starting SSTI Scan ===")
            ssti = SSTIScanner(args.target, args.verbose)
            results["ssti"] = ssti.run()

        if args.ssrf_scan:
            log_info("=== Starting SSRF Scan ===")
            ssrf = SSRFScanner(args.target, args.verbose)
            results["ssrf"] = ssrf.run()

        if args.lfi_scan:
            log_info("=== Starting LFI Scan ===")
            lfi = LFIScanner(args.target, args.verbose)
            results["lfi"] = lfi.run()

        if args.cors_check:
            log_info("=== Starting CORS Check ===")
            cors = CORSChecker(args.target, args.verbose)
            results["cors"] = cors.run()

        if args.jwt_scan:
            log_info("=== Starting JWT Scan ===")
            jwt = JWTScanner(args.target, args.verbose)
            results["jwt"] = jwt.run()

        if args.open_redirect:
            log_info("=== Starting Open Redirect Scan ===")
            open_redirect = OpenRedirectScanner(args.target, args.verbose)
            results["open_redirect"] = open_redirect.run()

        if args.graphql_scan:
            log_info("=== Starting GraphQL Scan ===")
            graphql = GraphQLScanner(args.target, args.verbose)
            results["graphql"] = graphql.run()

        if args.rate_limit:
            log_info("=== Starting Rate Limit Check ===")
            rate_limit = RateLimitChecker(args.target, args.verbose)
            results["rate_limit"] = rate_limit.run()

        if hasattr(args, "twofa_bypass") and args.twofa_bypass:
            log_info("=== Starting 2FA Bypass Check ===")
            twofa = TwoFABypass(args.target, args.verbose)
            results["2fa_bypass"] = twofa.run()

        if args.param_discovery:
            log_info("=== Starting Parameter Discovery ===")
            param = ParameterDiscovery(args.target, args.verbose)
            results["param_discovery"] = param.run()

        if args.blind_xss:
            log_info("=== Starting Blind XSS Scan ===")
            blind_xss = BlindXSSCollaborator(args.target, args.verbose)
            results["blind_xss"] = blind_xss.run()

        if args.secret_scan:
            log_info("=== Starting Secret Scanner ===")
            secret = SecretScanner(args.target, args.verbose)
            results["secret_scan"] = secret.run()

        if args.version_scan:
            log_info("=== Starting Version Scanner ===")
            version = VersionScanner(args.target, args.verbose)
            results["version_scan"] = version.run()

        if args.broken_link:
            log_info("=== Starting Broken Link Checker ===")
            broken = BrokenLinkChecker(args.target, args.threads, args.verbose)
            results["broken_link"] = broken.run()

        if args.fuzz:
            log_info("=== Starting Smart Fuzzing ===")
            fuzz = SmartFuzzing(args.target, args.fuzz_depth, args.verbose)
            results["smart_fuzzing"] = fuzz.run()

        if args.business_logic:
            log_info("=== Starting Business Logic Check ===")
            biz = BusinessLogicChecker(args.target, args.verbose)
            results["business_logic"] = biz.run()

        if args.race_condition:
            log_info("=== Starting Race Condition Detection ===")
            race = RaceConditionDetector(args.target, args.threads, args.verbose)
            results["race_condition"] = race.run()

        if args.chain_attack:
            log_info("=== Starting Chained Attack Scanner ===")
            chain = ChainedAttackScanner(args.target, args.verbose)
            results["chain_scan"] = chain.run()

        if args.static_analysis:
            log_info("=== Starting Static Analysis ===")
            static = StaticAnalysis(args.target, args.verbose)
            results["static_analysis"] = static.run()

        if args.api_scanner:
            log_info("=== Starting API Scanner ===")
            api = APIScanner(args.target, args.verbose)
            results["api_scanner"] = api.run()

        if args.rce_scan:
            log_info("=== Starting RCE Scanner ===")
            rce = RCEScanner(args.target, args.verbose)
            results["rce_scanner"] = rce.run()

        if args.dir_traversal:
            log_info("=== Starting Directory Traversal ===")
            traversal = DirTraversal(args.target, args.verbose)
            results["dir_traversal"] = traversal.run()

        if args.api_key_scan:
            log_info("=== Starting API Key Scanner ===")
            api_key = APIKeyScanner(args.target, args.verbose)
            results["api_key_scanner"] = api_key.run()

        if args.jwt_oauth:
            log_info("=== Starting JWT OAuth ===")
            jwt_oauth = JWTOAuthTester(args.target, args.verbose)
            results["jwt_oauth"] = jwt_oauth.run()

        if args.mobile_security:
            log_info("=== Starting Mobile Security ===")
            mobile = MobileSecurity(args.target, args.verbose)
            results["mobile_security"] = mobile.run()

        if args.ai_scan:
            log_info("=== Starting AI Scanner ===")
            ai = AIScanner(args.target, args.verbose)
            results["ai_scanner"] = ai.run()
            rec = (
                results["ai_scanner"].get("results", {}).get("recommended_command", "")
            )
            if rec:
                log_info(f"💡 {rec}")

            from modules.core.smart_engine import SmartEngine
            engine = SmartEngine(args.target, args.verbose)
            print(engine.run())
            sys.exit(0)
            engine = SmartEngine(args.target, args.verbose)
            print(engine.run())
            sys.exit(0)
        
        if args.smart_scan:
            log_info("=== Starting Smart Scan (Auto Throttle) ===")
            smart = AutoThrottle(args.target, args.verbose)
            results["auto_throttle"] = smart.run()
            rec = results["auto_throttle"].get("results", {})
            log_info(
                f"💡 Recommended command: python main.py web -t {args.target} --sqli --xss --dir-bruteforce -th {rec.get('recommended_threads', 5)} -v"
            )

        if args.auto_advanced:
            from modules.web.auto_advanced import AdvancedAuto

            log_info("=== Starting Advanced Auto Mode ===")
            smart = AdvancedAuto(args.target, args.verbose)
            results["advanced_auto"] = smart.run()
            rec = results["advanced_auto"]
            log_info(f"💡 Detected Type: {rec.get('detected_type')}")
            log_info(
                f"💡 Recommended: python main.py web -t {args.target} {' '.join(rec.get('recommended_modules', []))} -th {args.threads} -v"
            )

        if args.exploit:
            log_info("=== Starting Exploit Module ===")
            exploit = ExploitModule(args.target, args.verbose)
            results["exploit"] = exploit.run()

        if args.nikto:
            log_info("=== Starting Nikto-style Scan ===")
            nikto = NiktoStyleScanner(args.target, args.verbose)
            results["nikto_style"] = nikto.run()

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log_success(f"All results saved to {args.output}")

        if args.report:
            from modules.reporting.html_report import HTMLReport

            report_name = args.output.replace(".json", ".html")
            report = HTMLReport(args.output, report_name)
            report.generate()

        if hasattr(args, "report_pdf") and args.report_pdf:
            from modules.reporting.pdf_report import PDFReport

            PDFReport(args.output).generate()

        if hasattr(args, "report_txt") and args.report_txt:
            from modules.reporting.pdf_report import TXTReport

            TXTReport(args.output).generate()

        log_info("GOODS-DRAGON - Web scan completed. Stay secure!")

    # ------- Execute scan -------
    elif args.command == "scan":
        from modules.exploit.dev import ExploitDev
        from modules.scan.host_discovery import HostDiscovery
        from modules.scan.password_crack import PasswordCracker
        from modules.scan.portscan import PortScanner
        from modules.scan.s3 import S3Finder
        from modules.scan.ssl_check import SSLChecker

        HackerUI.scan_header(args.target, "Network Scanner")
        log_info(f"GOODS-DRAGON - Scan started on: {args.target}")
        results = {}

        if args.ping_sweep:
            log_info("=== Starting Host Discovery ===")
            discovery = HostDiscovery(args.target, args.threads, args.verbose)
            results["host_discovery"] = discovery.run()

        if not args.ping_sweep:
            log_info("=== Starting Port Scan ===")
            scanner = PortScanner(
                target=args.target,
                ports=args.ports,
                threads=args.threads,
                verbose=args.verbose,
                banner=args.banner,
            )
            results["port_scan"] = scanner.run()

        if args.s3_find:
            log_info("=== Starting S3 Bucket Finder ===")
            s3 = S3Finder(args.target, args.threads, args.verbose)
            results["s3"] = s3.run()

        if args.ssl_check:
            log_info("=== Starting SSL/TLS Check ===")
            ssl_check = SSLChecker(args.target, args.verbose)
            results["ssl_check"] = ssl_check.run()

        if args.bruteforce:
            from modules.scan.bruteforce import BruteForce

            log_info("=== Starting Brute Force ===")
            bf = BruteForce(
                target=args.target,
                port=args.ports.split(",")[0] if "," in args.ports else args.ports,
                service=args.service,
                userlist=args.userlist,
                passlist=args.passlist,
                threads=args.threads,
                verbose=args.verbose,
            )
            results["bruteforce"] = bf.run()

        if args.password_crack:
            log_info("=== Starting Password Cracking ===")
            crack = PasswordCracker(args.target, args.verbose)
            results["password_crack"] = crack.run()

        if args.exploit_dev:
            log_info("=== Starting Exploit Development ===")
            dev = ExploitDev(args.target, args.verbose)
            results["exploit_dev"] = dev.run()

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log_success(f"Results saved to {args.output}")

        if args.report:
            from modules.reporting.html_report import HTMLReport

            report_name = args.output.replace(".json", ".html")
            report = HTMLReport(args.output, report_name)
            report.generate()

        if hasattr(args, "report_pdf") and args.report_pdf:
            from modules.reporting.pdf_report import PDFReport

            PDFReport(args.output).generate()

        if hasattr(args, "report_txt") and args.report_txt:
            from modules.reporting.pdf_report import TXTReport

            TXTReport(args.output).generate()

        log_info("GOODS-DRAGON - Scan completed. Stay secure!")


if __name__ == "__main__":
    main()
