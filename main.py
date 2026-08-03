# ============================================================
# Dragon Eye - Advanced Pentesting & Bug Bounty Tool
# Copyright (c) 2026 zeus (z4). All rights reserved.
# This software is proprietary and confidential.
# Unauthorized copying, distribution, or use is strictly prohibited.
# ============================================================
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import json
import os
from core.logger import log_info, log_error, log_success, log_warning

# ------- Dragon Eye Banner -------
def show_banner():
    banner = r"""
    ██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔═══██╗████╗  ██║
    ██║  ██║██████╔╝███████║██║   ██║██║   ██║██╔██╗ ██║
    ██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║
    ██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
                        EYE v1.0
    """
    print(banner)
    print(f"{'='*50}")
    print(f"    Author : zeus (z4)")
    print(f"    Telegram : @iM_z4")
    print(f"{'='*50}\n")

# ------- Professional Interactive Menu -------
def interactive_menu():
    os.system('clear')
    show_banner()
    
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                    MAIN MENU                            ║
    ╠══════════════════════════════════════════════════════════╣
    ║  [1]  Reconnaissance (Subdomain, Wayback, Active)       ║
    ║  [2]  Web Vulnerabilities (SQLi, XSS, CMS, CVE, etc)    ║
    ║  [3]  Network Scan (Port, Host Discovery, SSL, S3)      ║
    ║  [4]  Subdomain Takeover Check                          ║
    ║  [5]  Cloud Enumeration (AWS, Azure, GCP)               ║
    ║  [6]  Git Repository Scanner                            ║
    ║  [7]  WAF Detection                                     ║
    ║  [8]  Public Info (IP, Country, Domain)                 ║
    ║  [9]  Phone Info (Mobile Number Lookup)                 ║
    ║  [10] Brute Force (SSH/FTP/RDP)                         ║
    ║  [11] IDOR Scanner                                      ║
    ║  [12] SSTI Scanner                                      ║
    ║  [13] SSRF Scanner                                      ║
    ║  [14] LFI/RFI Scanner                                   ║
    ║  [15] CORS Checker                                      ║
    ║  [16] JWT Scanner                                       ║
    ║  [17] Open Redirect Scanner                             ║
    ║  [18] GraphQL Scanner                                   ║
    ║  [19] Rate Limit Checker                                ║
    ║  [20] 2FA Bypass Checker                                ║
    ║  [21] Parameter Discovery                               ║
    ║  [22] Exploit Module (Metasploit Style)                 ║
    ║  [23] Nikto-style Scanner                               ║
    ║  [24] Auto-Scanner (Run All Modules)                    ║
    ║  [25] Blind XSS Collaborator                            ║
    ║  [26] Secret Scanner (API Keys, Tokens)                 ║
    ║  [27] Version Scanner                                   ║
    ║  [28] Broken Link Checker                               ║
    ║  [29] Smart Fuzzing                                     ║
    ║  [30] Business Logic Checker                            ║
    ║  [31] Race Condition Detector                           ║
    ║  [32] Chained Attack Scanner                            ║
    ║  [33] Static Analysis (Code Review)                     ║
    ║  [34] Shodan Integration                                ║
    ║  [35] Censys Integration                                ║
    ║  [36] Generate HackerOne Report                         ║
    ║  [37] Generate Report from JSON                         ║
    ║  [0]  Exit                                              ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    choice = input("Select an option [0-37] > ").strip()
    
    if choice == "0":
        log_info("Exiting Dragon Eye. Stay secure!")
        sys.exit(0)
    
    target = input("Enter target (domain/IP/Phone) > ").strip()
    if not target:
        log_error("Target cannot be empty.")
        return
    
    threads = input("Threads (default 30) > ").strip()
    threads = int(threads) if threads.isdigit() else 30
    verbose = input("Verbose mode? (y/n) > ").strip().lower() == 'y'
    report = input("Generate HTML report? (y/n) > ").strip().lower() == 'y'
    
    cmd = "python main.py "
    
    if choice == "1":
        cmd += f"recon -t {target} --active-scan --wayback -th {threads}"
    elif choice == "2":
        cmd += f"web -t {target} --sqli --xss --cms-detect --cve-scan --headers-check --js-deps --tech-detect -th {threads}"
    elif choice == "3":
        cmd += f"scan -t {target} --ssl-check -th {threads}"
    elif choice == "4":
        cmd += f"recon -t {target} --takeover -th {threads}"
    elif choice == "5":
        cmd += f"recon -t {target} --cloud-enum -th {threads}"
    elif choice == "6":
        cmd += f"web -t {target} --git-scan -th {threads}"
    elif choice == "7":
        cmd += f"web -t {target} --waf-detect -th {threads}"
    elif choice == "8":
        cmd += f"recon -t {target} --public-info -th {threads}"
    elif choice == "9":
        cmd += f"recon -t {target} --phone-info -th {threads}"
    elif choice == "10":
        service = input("Service (ssh/ftp/rdp) [default: ssh] > ").strip() or "ssh"
        userlist = input("Usernames (comma separated) [default: root,admin] > ").strip() or "root,admin"
        passlist = input("Passwords (comma separated) [default: password,123456] > ").strip() or "password,123456"
        cmd += f"scan -t {target} --bruteforce --service {service} --userlist {userlist} --passlist {passlist} -th {threads}"
    elif choice == "11":
        cmd += f"web -t {target} --idor-scan -th {threads}"
    elif choice == "12":
        cmd += f"web -t {target} --ssti-scan -th {threads}"
    elif choice == "13":
        cmd += f"web -t {target} --ssrf-scan -th {threads}"
    elif choice == "14":
        cmd += f"web -t {target} --lfi-scan -th {threads}"
    elif choice == "15":
        cmd += f"web -t {target} --cors-check -th {threads}"
    elif choice == "16":
        cmd += f"web -t {target} --jwt-scan -th {threads}"
    elif choice == "17":
        cmd += f"web -t {target} --open-redirect -th {threads}"
    elif choice == "18":
        cmd += f"web -t {target} --graphql-scan -th {threads}"
    elif choice == "19":
        cmd += f"web -t {target} --rate-limit -th {threads}"
    elif choice == "20":
        cmd += f"web -t {target} --2fa-bypass -th {threads}"
    elif choice == "21":
        cmd += f"web -t {target} --param-discovery -th {threads}"
    elif choice == "22":
        cmd += f"web -t {target} --exploit -th {threads}"
    elif choice == "23":
        cmd += f"web -t {target} --nikto -th {threads}"
    elif choice == "24":
        cmd += f"recon -t {target} --auto -th {threads}"
    elif choice == "25":
        cmd += f"web -t {target} --blind-xss -th {threads}"
    elif choice == "26":
        cmd += f"web -t {target} --secret-scan -th {threads}"
    elif choice == "27":
        cmd += f"web -t {target} --version-scan -th {threads}"
    elif choice == "28":
        cmd += f"web -t {target} --broken-link -th {threads}"
    elif choice == "29":
        cmd += f"web -t {target} --fuzz --fuzz-depth 50 -th {threads}"
    elif choice == "30":
        cmd += f"web -t {target} --business-logic -th {threads}"
    elif choice == "31":
        cmd += f"web -t {target} --race-condition -th {threads}"
    elif choice == "32":
        cmd += f"web -t {target} --chained-attack -th {threads}"
    elif choice == "33":
        cmd += f"web -t {target} --static-analysis -th {threads}"
    elif choice == "34":
        key = input("Enter Shodan API Key > ").strip()
        cmd += f"recon -t {target} --shodan --shodan-key {key} -th {threads}"
    elif choice == "35":
        cid = input("Enter Censys API ID > ").strip()
        secret = input("Enter Censys API Secret > ").strip()
        cmd += f"recon -t {target} --censys --censys-id {cid} --censys-secret {secret} -th {threads}"
    elif choice == "36":
        cmd += f"recon -t {target} --h1-report -th {threads}"
    elif choice == "37":
        json_file = input("Enter JSON file path [reports/recon_output.json] > ").strip() or "reports/recon_output.json"
        cmd = f"python main.py --report {json_file}"
    else:
        log_error("Invalid choice.")
        return
    
    if verbose:
        cmd += " -v"
    if report and choice not in ["34", "35", "36", "37"]:
        cmd += " --report"
    
    log_info(f"Executing: {cmd}")
    os.system(cmd)

# ------- Main Entry -------
def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(
        description="Dragon Eye - Advanced Pentesting & Bug Bounty Tool (Created by zeus @iM_z4)",
        epilog="For more info, contact @iM_z4 on Telegram"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ----- Subcommand: recon -----
    recon_parser = subparsers.add_parser("recon", help="Reconnaissance: Subdomains, Wayback, Active Scan, Takeover, Cloud Enum, Public Info, Phone Info, Auto-Scan, Shodan, Censys, HackerOne Report")
    recon_parser.add_argument("-t", "--target", required=True, help="Target domain (e.g. example.com) or IP or country code or phone number")
    recon_parser.add_argument("-w", "--wordlist", default="wordlists/subdomains.txt", help="Wordlist path")
    recon_parser.add_argument("--wayback", action="store_true", help="Fetch historical URLs from Wayback Machine")
    recon_parser.add_argument("--active-scan", action="store_true", help="Active subdomain scan with HTTP/HTTPS checks")
    recon_parser.add_argument("--takeover", action="store_true", help="Check for subdomain takeover vulnerabilities")
    recon_parser.add_argument("--cloud-enum", action="store_true", help="Enumerate cloud resources (AWS, Azure, GCP)")
    recon_parser.add_argument("--public-info", action="store_true", help="Get public info (IP geolocation, country details, domain info)")
    recon_parser.add_argument("--phone-info", action="store_true", help="Get phone number information (country, operator, type)")
    recon_parser.add_argument("--auto", action="store_true", help="Run all modules automatically (full scan)")
    recon_parser.add_argument("--auto-output", default="reports/auto_scan.json", help="Auto-scan output file")
    recon_parser.add_argument("--shodan", action="store_true", help="Shodan integration")
    recon_parser.add_argument("--shodan-key", help="Shodan API key")
    recon_parser.add_argument("--censys", action="store_true", help="Censys integration")
    recon_parser.add_argument("--censys-id", help="Censys API ID")
    recon_parser.add_argument("--censys-secret", help="Censys API secret")
    recon_parser.add_argument("--h1-report", action="store_true", help="Generate HackerOne format report")
    recon_parser.add_argument("--report", action="store_true", help="Generate HTML report from JSON output")
    recon_parser.add_argument("-th", "--threads", type=int, default=30, help="Number of threads")
    recon_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed logs")
    recon_parser.add_argument("-o", "--output", default="reports/recon_output.json", help="Output file path")

    # ----- Subcommand: web -----
    web_parser = subparsers.add_parser("web", help="Web vulnerabilities: SQLi, XSS, CMS, CVE, Headers, JS, Tech, Git, WAF, IDOR, SSTI, SSRF, LFI, CORS, JWT, Open Redirect, GraphQL, Rate Limit, 2FA, Param Discovery, Blind XSS, Secret Scanner, Version Scanner, Broken Link, Proxy, Exploit, Nikto, Smart Fuzzing, Business Logic, Race Condition, Chained Attack, Static Analysis")
    web_parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. http://testphp.vulnweb.com)")
    web_parser.add_argument("--sqli", action="store_true", help="Enable SQL Injection scan")
    web_parser.add_argument("--xss", action="store_true", help="Enable XSS scan")
    web_parser.add_argument("--log-check", action="store_true", help="Check for sensitive files (.env, .git, logs)")
    web_parser.add_argument("--login-bypass", action="store_true", help="Test login form bypass")
    web_parser.add_argument("--dir-bruteforce", action="store_true", help="Bruteforce hidden directories")
    web_parser.add_argument("--cms-detect", action="store_true", help="Detect CMS (WordPress, Joomla, Drupal, etc.)")
    web_parser.add_argument("--cve-scan", action="store_true", help="Check for known CVEs in detected technologies")
    web_parser.add_argument("--js-deps", action="store_true", help="Scan for vulnerable JavaScript libraries")
    web_parser.add_argument("--tech-detect", action="store_true", help="Detect web technologies (servers, frameworks, languages)")
    web_parser.add_argument("--headers-check", action="store_true", help="Check security headers (CSP, HSTS, XFO, etc.)")
    web_parser.add_argument("--git-scan", action="store_true", help="Scan for exposed Git repositories")
    web_parser.add_argument("--waf-detect", action="store_true", help="Detect Web Application Firewalls")
    web_parser.add_argument("--idor-scan", action="store_true", help="Scan for IDOR vulnerabilities")
    web_parser.add_argument("--ssti-scan", action="store_true", help="Scan for Server-Side Template Injection")
    web_parser.add_argument("--ssrf-scan", action="store_true", help="Scan for Server-Side Request Forgery")
    web_parser.add_argument("--lfi-scan", action="store_true", help="Scan for Local/Remote File Inclusion")
    web_parser.add_argument("--cors-check", action="store_true", help="Check for CORS misconfigurations")
    web_parser.add_argument("--jwt-scan", action="store_true", help="Scan for JWT tokens")
    web_parser.add_argument("--open-redirect", action="store_true", help="Scan for Open Redirect vulnerabilities")
    web_parser.add_argument("--graphql-scan", action="store_true", help="Scan for GraphQL endpoints")
    web_parser.add_argument("--rate-limit", action="store_true", help="Check for rate limiting")
    web_parser.add_argument("--2fa-bypass", action="store_true", help="Check for 2FA implementation")
    web_parser.add_argument("--param-discovery", action="store_true", help="Discover hidden parameters in URLs")
    web_parser.add_argument("--blind-xss", action="store_true", help="Test for Blind XSS vulnerabilities")
    web_parser.add_argument("--secret-scan", action="store_true", help="Scan for secrets, API keys, and tokens")
    web_parser.add_argument("--version-scan", action="store_true", help="Scan for software versions")
    web_parser.add_argument("--broken-link", action="store_true", help="Check for broken links")
    web_parser.add_argument("--fuzz", action="store_true", help="Smart fuzzing for new vulnerabilities")
    web_parser.add_argument("--fuzz-depth", type=int, default=100, help="Fuzzing depth per parameter")
    web_parser.add_argument("--business-logic", action="store_true", help="Check for business logic flaws")
    web_parser.add_argument("--race-condition", action="store_true", help="Detect race conditions")
    web_parser.add_argument("--chained-attack", action="store_true", help="Scan for chained attacks")
    web_parser.add_argument("--static-analysis", action="store_true", help="Static code analysis")
    web_parser.add_argument("--proxy", action="store_true", help="Start proxy server (Burp Suite style)")
    web_parser.add_argument("--proxy-port", type=int, default=8080, help="Proxy port (default: 8080)")
    web_parser.add_argument("--exploit", action="store_true", help="Run exploit module (Metasploit style)")
    web_parser.add_argument("--nikto", action="store_true", help="Run Nikto-style vulnerability scanner")
    web_parser.add_argument("--report", action="store_true", help="Generate HTML report from JSON output")
    web_parser.add_argument("-w", "--wordlist", default="wordlists/dirs.txt", help="Wordlist for directory bruteforce")
    web_parser.add_argument("-th", "--threads", type=int, default=30, help="Number of threads")
    web_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed logs")
    web_parser.add_argument("-o", "--output", default="reports/web_output.json", help="Output file path")
    web_parser.add_argument("--script", help="Run a custom script (automate, exploits, report)")
    # ----- Subcommand: scan -----
    scan_parser = subparsers.add_parser("scan", help="Network scanning: Port Scanner, Host Discovery, S3, SSL, Brute Force")
    scan_parser.add_argument("-t", "--target", required=True, help="Target IP, domain, or subnet (e.g. 192.168.1.0/24)")
    scan_parser.add_argument("-p", "--ports", default="21,22,23,25,80,443,3306,3389,8080", help="Port range (e.g. 1-1000 or 80,443)")
    scan_parser.add_argument("--ping-sweep", action="store_true", help="Discover alive hosts on the network (subnet required)")
    scan_parser.add_argument("--s3-find", action="store_true", help="Search for open S3 buckets")
    scan_parser.add_argument("--ssl-check", action="store_true", help="Check SSL/TLS certificate validity")
    scan_parser.add_argument("--bruteforce", action="store_true", help="Brute force SSH/FTP/RDP credentials")
    scan_parser.add_argument("--service", choices=["ssh", "ftp", "rdp"], default="ssh", help="Service to brute force")
    scan_parser.add_argument("--userlist", default="root,admin", help="List of usernames (comma separated)")
    scan_parser.add_argument("--passlist", default="password,123456,admin", help="List of passwords (comma separated)")
    scan_parser.add_argument("--report", action="store_true", help="Generate HTML report from JSON output")
    scan_parser.add_argument("-b", "--banner", action="store_true", help="Grab service banners")
    scan_parser.add_argument("-th", "--threads", type=int, default=50, help="Number of threads")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed logs")
    scan_parser.add_argument("-o", "--output", default="reports/scan_output.json", help="Output file path")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # ------- Execute recon -------
    if args.command == "recon":
        # ----- Auto-Scanner -----
        if args.auto:
            from modules.web.auto_scanner import AutoScanner
            log_info("=== Starting Auto-Scanner ===")
            scanner = AutoScanner(
                target=args.target,
                verbose=args.verbose,
                threads=args.threads,
                output=args.auto_output
            )
            results = scanner.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Auto-scan results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport
                report_name = args.output.replace('.json', '.html')
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("Dragon Eye - Auto-scan completed.")
            sys.exit(0)

        # ----- HackerOne Report -----
        if args.h1_report:
            from modules.reporting.hackerone_format import HackerOneReport
            log_info("=== Generating HackerOne Report ===")
            report = HackerOneReport(args.output, "hackerone_report.md")
            report.generate()
            log_info("Dragon Eye - HackerOne Report completed.")
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
                report_name = args.output.replace('.json', '.html')
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("Dragon Eye - Shodan Integration completed.")
            sys.exit(0)

        # ----- Censys Integration -----
        if args.censys:
            from modules.recon.censys import CensysIntegration
            log_info("=== Starting Censys Integration ===")
            censys = CensysIntegration(args.target, args.censys_id, args.censys_secret, args.verbose)
            results = censys.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport
                report_name = args.output.replace('.json', '.html')
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("Dragon Eye - Censys Integration completed.")
            sys.exit(0)

        # Check if public-info is requested
        if args.public_info:
            from modules.recon.public_info import PublicInfo
            log_info(f"Dragon Eye - Public Info gathering on: {args.target}")
            pi = PublicInfo(args.target, args.verbose)
            results = pi.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport
                report_name = args.output.replace('.json', '.html')
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("Dragon Eye - Public Info completed.")
            sys.exit(0)

        # Check if phone-info is requested
        if args.phone_info:
            from modules.recon.phone_info import PhoneInfo
            log_info(f"Dragon Eye - Phone Info gathering on: {args.target}")
            pi = PhoneInfo(args.target, args.verbose)
            results = pi.run()
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            log_success(f"Results saved to {args.output}")
            if args.report:
                from modules.reporting.html_report import HTMLReport
                report_name = args.output.replace('.json', '.html')
                report = HTMLReport(args.output, report_name)
                report.generate()
            log_info("Dragon Eye - Phone Info completed.")
            sys.exit(0)

        from modules.recon.subdomain import SubdomainFinder
        from modules.recon.wayback import WaybackScanner
        from modules.recon.active_scan import ActiveSubdomainScanner
        
        log_info(f"Dragon Eye - Recon started on: {args.target}")
        results = {}
        
        # Subdomain Enumeration
        finder = SubdomainFinder(
            domain=args.target,
            wordlist_path=args.wordlist,
            threads=args.threads,
            verbose=args.verbose
        )
        results["subdomains"] = finder.run()
        
        # Wayback URLs
        if args.wayback:
            log_info("=== Starting Wayback URL Fetch ===")
            wayback = WaybackScanner(args.target, args.verbose)
            results["wayback"] = wayback.run()
        
        # Active Subdomain Scan
        if args.active_scan:
            log_info("=== Starting Active Subdomain Scan ===")
            active = ActiveSubdomainScanner(args.target, args.wordlist, args.threads, args.verbose)
            results["active_scan"] = active.run()
        
        # Subdomain Takeover
        if args.takeover:
            from modules.recon.takeover import SubdomainTakeover
            log_info("=== Starting Subdomain Takeover Check ===")
            sub_list = results.get("subdomains", {}).get("subdomains", [])
            if sub_list:
                sub_names = [s.get("subdomain", "") for s in sub_list if s.get("subdomain")]
                if sub_names:
                    takeover = SubdomainTakeover(sub_names, args.verbose)
                    results["takeover"] = takeover.run()
                else:
                    log_warning("No subdomains found to check for takeover.")
            else:
                log_warning("Run subdomain enumeration first (--takeover needs subdomain list).")
        
        # Cloud Enumeration
        if args.cloud_enum:
            from modules.recon.cloud_enum import CloudEnum
            log_info("=== Starting Cloud Enumeration ===")
            cloud = CloudEnum(args.target, args.threads, args.verbose)
            results["cloud_enum"] = cloud.run()
        
        # Save results
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log_success(f"Results saved to {args.output}")
        
        # Generate HTML report
        if args.report:
            from modules.reporting.html_report import HTMLReport
            report_name = args.output.replace('.json', '.html')
            report = HTMLReport(args.output, report_name)
            report.generate()
        
        log_info("Dragon Eye - Recon completed. Stay secure!")

    # ------- Execute web -------
    elif args.command == "web":
        from modules.web.disclosure import InfoDisclosureScanner
        from modules.web.sqli import SQLiScanner
        from modules.web.xss import XSSScanner
        from modules.web.login_bypass import LoginBypassScanner
        from modules.web.dir_bruteforce import DirBruteforce
        from modules.web.cms import CMSDetector
        from modules.web.cve_scan import CVEScanner
        from modules.web.js_deps import JSDependencyScanner
        from modules.web.tech_detect import TechnologyDetector
        from modules.web.headers_check import SecurityHeadersChecker
        from modules.web.git_scan import GitScanner
        from modules.web.waf_detect import WAFDetector
        from modules.web.idor import IDORScanner
        from modules.web.ssti import SSTIScanner
        from modules.web.ssrf import SSRFScanner
        from modules.web.lfi import LFIScanner
        from modules.web.cors import CORSChecker
        from modules.web.jwt import JWTScanner
        from modules.web.open_redirect import OpenRedirectScanner
        from modules.web.graphql import GraphQLScanner
        from modules.web.rate_limit import RateLimitChecker
        from modules.web.twofa_bypass import TwoFABypass
        from modules.web.param_discovery import ParameterDiscovery
        from modules.web.proxy import ProxyServer
        from modules.exploit.exploit import ExploitModule
        from modules.web.nikto_style import NiktoStyleScanner
        from modules.web.collaborator.blind_xss import BlindXSSCollaborator
        from modules.web.secret_scanner import SecretScanner
        from modules.web.version_scanner import VersionScanner
        from modules.web.broken_link import BrokenLinkChecker
        from modules.web.smart_fuzzing import SmartFuzzing
        from modules.web.business_logic import BusinessLogicChecker
        from modules.web.race_condition import RaceConditionDetector
        from modules.web.chained_attack import ChainedAttackScanner
        from modules.web.static_analysis import StaticAnalysis
        
        # ----- Proxy Server (standalone) -----
        if args.proxy:
            log_info("=== Starting Proxy Server ===")
            proxy = ProxyServer(port=args.proxy_port, verbose=args.verbose)
            log_info("Press Ctrl+C to stop the proxy")
            try:
                proxy.run()
            except KeyboardInterrupt:
                log_info("Proxy stopped")
            sys.exit(0)
        
        log_info(f"Dragon Eye - Web scanner started on: {args.target}")
        results = {}
        
        # Info Disclosure
        if args.log_check:
            log_info("=== Starting Info Disclosure Scan ===")
            disclosure = InfoDisclosureScanner(args.target, args.verbose)
            results["info_disclosure"] = disclosure.run()
        
        # SQL Injection
        if args.sqli:
            log_info("=== Starting SQL Injection Scan ===")
            sqli = SQLiScanner(args.target, args.verbose)
            results["sqli"] = sqli.run()
        
        # XSS Scanner
        if args.xss:
            log_info("=== Starting XSS Scan ===")
            xss = XSSScanner(args.target, args.verbose, args.threads)
            results["xss"] = xss.run()
        
        # Login Bypass
        if args.login_bypass:
            log_info("=== Starting Login Bypass Scan ===")
            login = LoginBypassScanner(args.target, args.verbose)
            results["login_bypass"] = login.run()
        
        # Directory Bruteforce
        if args.dir_bruteforce:
            log_info("=== Starting Directory Bruteforce ===")
            dir_bf = DirBruteforce(
                target=args.target,
                wordlist_path=args.wordlist,
                threads=args.threads,
                verbose=args.verbose
            )
            results["dir_bruteforce"] = dir_bf.run()
        
        # CMS Detection
        if args.cms_detect:
            log_info("=== Starting CMS Detection ===")
            cms = CMSDetector(args.target, args.verbose)
            results["cms"] = cms.run()
        
        # Technology Detector
        if args.tech_detect or (args.cve_scan and not args.tech_detect and not args.cms_detect):
            if not args.tech_detect and args.cve_scan:
                log_info("Running Tech detection for CVE matching...")
            log_info("=== Starting Technology Detection ===")
            tech = TechnologyDetector(args.target, args.verbose)
            results["tech_detect"] = tech.run()
        elif args.tech_detect:
            log_info("=== Starting Technology Detection ===")
            tech = TechnologyDetector(args.target, args.verbose)
            results["tech_detect"] = tech.run()
        
        # CMS Detection for CVE
        if args.cve_scan and not args.cms_detect:
            log_info("Running CMS detection for CVE matching...")
            cms = CMSDetector(args.target, args.verbose)
            results["cms"] = cms.run()
        
        # CVE Scan
        if args.cve_scan:
            log_info("=== Starting CVE Vulnerability Scan ===")
            cve_scanner = CVEScanner(
                target=args.target,
                cms_data=results.get("cms", {}),
                tech_data=results.get("tech_detect", {}),
                verbose=args.verbose
            )
            results["cve_scan"] = cve_scanner.run()
        
        # JS Dependency Scanner
        if args.js_deps:
            log_info("=== Starting JS Dependency Scan ===")
            js = JSDependencyScanner(args.target, args.verbose)
            results["js_deps"] = js.run()
        
        # Security Headers Checker
        if args.headers_check:
            log_info("=== Starting Security Headers Check ===")
            headers = SecurityHeadersChecker(args.target, args.verbose)
            results["headers_check"] = headers.run()
        
        # Git Scanner
        if args.git_scan:
            log_info("=== Starting Git Repository Scan ===")
            git = GitScanner(args.target, args.verbose)
            results["git_scan"] = git.run()
        
        # WAF Detection
        if args.waf_detect:
            log_info("=== Starting WAF Detection ===")
            waf = WAFDetector(args.target, args.verbose)
            results["waf_detect"] = waf.run()
        
        # IDOR Scanner
        if args.idor_scan:
            log_info("=== Starting IDOR Scan ===")
            idor = IDORScanner(args.target, args.verbose)
            results["idor"] = idor.run()
        
        # SSTI Scanner
        if args.ssti_scan:
            log_info("=== Starting SSTI Scan ===")
            ssti = SSTIScanner(args.target, args.verbose)
            results["ssti"] = ssti.run()
        
        # SSRF Scanner
        if args.ssrf_scan:
            log_info("=== Starting SSRF Scan ===")
            ssrf = SSRFScanner(args.target, args.verbose)
            results["ssrf"] = ssrf.run()
        
        # LFI Scanner
        if args.lfi_scan:
            log_info("=== Starting LFI Scan ===")
            lfi = LFIScanner(args.target, args.verbose)
            results["lfi"] = lfi.run()
        
        # CORS Checker
        if args.cors_check:
            log_info("=== Starting CORS Check ===")
            cors = CORSChecker(args.target, args.verbose)
            results["cors"] = cors.run()
        
        # JWT Scanner
        if args.jwt_scan:
            log_info("=== Starting JWT Scan ===")
            jwt = JWTScanner(args.target, args.verbose)
            results["jwt"] = jwt.run()
        
        # Open Redirect Scanner
        if args.open_redirect:
            log_info("=== Starting Open Redirect Scan ===")
            open_redirect = OpenRedirectScanner(args.target, args.verbose)
            results["open_redirect"] = open_redirect.run()
        
        # GraphQL Scanner
        if args.graphql_scan:
            log_info("=== Starting GraphQL Scan ===")
            graphql = GraphQLScanner(args.target, args.verbose)
            results["graphql"] = graphql.run()
        
        # Rate Limit Checker
        if args.rate_limit:
            log_info("=== Starting Rate Limit Check ===")
            rate_limit = RateLimitChecker(args.target, args.verbose)
            results["rate_limit"] = rate_limit.run()
        
        # 2FA Bypass Checker
        if hasattr(args, 'twofa_bypass') and args.twofa_bypass:
            log_info("=== Starting 2FA Bypass Check ===")
            twofa = TwoFABypass(args.target, args.verbose)
            results["2fa_bypass"] = twofa.run()
        
        # Parameter Discovery
        if args.param_discovery:
            log_info("=== Starting Parameter Discovery ===")
            param = ParameterDiscovery(args.target, args.verbose)
            results["param_discovery"] = param.run()
        
        # Blind XSS
        if args.blind_xss:
            log_info("=== Starting Blind XSS Scan ===")
            blind_xss = BlindXSSCollaborator(args.target, args.verbose)
            results["blind_xss"] = blind_xss.run()
        
        # Secret Scanner
        if args.secret_scan:
            log_info("=== Starting Secret Scanner ===")
            secret = SecretScanner(args.target, args.verbose)
            results["secret_scan"] = secret.run()
        
        # Version Scanner
        if args.version_scan:
            log_info("=== Starting Version Scanner ===")
            version = VersionScanner(args.target, args.verbose)
            results["version_scan"] = version.run()
        
        # Broken Link Checker
        if args.broken_link:
            log_info("=== Starting Broken Link Checker ===")
            broken = BrokenLinkChecker(args.target, args.threads, args.verbose)
            results["broken_link"] = broken.run()
        
        # Smart Fuzzing
        if args.fuzz:
            log_info("=== Starting Smart Fuzzing ===")
            fuzz = SmartFuzzing(args.target, args.fuzz_depth, args.verbose)
            results["smart_fuzzing"] = fuzz.run()
        
        # Business Logic Checker
        if args.business_logic:
            log_info("=== Starting Business Logic Check ===")
            biz = BusinessLogicChecker(args.target, args.verbose)
            results["business_logic"] = biz.run()
        
        # Race Condition Detector
        if args.race_condition:
            log_info("=== Starting Race Condition Detection ===")
            race = RaceConditionDetector(args.target, args.threads, args.verbose)
            results["race_condition"] = race.run()
        
        # Chained Attack Scanner
        if args.chained_attack:
            log_info("=== Starting Chained Attack Scanner ===")
            chain = ChainedAttackScanner(args.target, args.verbose)
            results["chained_attack"] = chain.run()
        
        # Static Analysis
        if args.static_analysis:
            log_info("=== Starting Static Analysis ===")
            static = StaticAnalysis(args.target, args.verbose)
            results["static_analysis"] = static.run()
        
        # Exploit Module
        if args.exploit:
            log_info("=== Starting Exploit Module ===")
            exploit = ExploitModule(args.target, args.verbose)
            results["exploit"] = exploit.run()
        
        # Nikto-style Scanner
        if args.nikto:
            log_info("=== Starting Nikto-style Scan ===")
            nikto = NiktoStyleScanner(args.target, args.verbose)
            results["nikto_style"] = nikto.run()
        
        # ----- Custom Scripts -----
        if args.script:
            if args.script == "automate":
                from scripts.automate import AutoScript
                script = AutoScript(args.target, args.verbose)
                script.run()
                sys.exit(0)
            elif args.script == "exploits":
                from scripts.exploits import ExploitScripts
                script = ExploitScripts(args.target, args.verbose)
                script.run()
                sys.exit(0)
            elif args.script == "report":
                from scripts.report_gen import ReportGenerator
                script = ReportGenerator(args.output, "custom_report.txt")
                script.generate()
                sys.exit(0)
            else:
                log_error(f"Unknown script: {args.script}")
                sys.exit(1)
        
        # Save results
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log_success(f"All results saved to {args.output}")
        
        # Generate HTML report
        if args.report:
            from modules.reporting.html_report import HTMLReport
            report_name = args.output.replace('.json', '.html')
            report = HTMLReport(args.output, report_name)
            report.generate()
        
        log_info("Dragon Eye - Web scan completed. Stay secure!")

    # ------- Execute scan -------
    elif args.command == "scan":
        from modules.scan.portscan import PortScanner
        from modules.scan.s3 import S3Finder
        from modules.scan.ssl_check import SSLChecker
        from modules.scan.host_discovery import HostDiscovery
        
        log_info(f"Dragon Eye - Scan started on: {args.target}")
        results = {}
        
        # Host Discovery
        if args.ping_sweep:
            log_info("=== Starting Host Discovery ===")
            discovery = HostDiscovery(args.target, args.threads, args.verbose)
            results["host_discovery"] = discovery.run()
        
        # Port Scanner
        if not args.ping_sweep:
            log_info("=== Starting Port Scan ===")
            scanner = PortScanner(
                target=args.target,
                ports=args.ports,
                threads=args.threads,
                verbose=args.verbose,
                banner=args.banner
            )
            results["port_scan"] = scanner.run()
        
        # S3 Bucket Finder
        if args.s3_find:
            log_info("=== Starting S3 Bucket Finder ===")
            s3 = S3Finder(args.target, args.threads, args.verbose)
            results["s3"] = s3.run()
        
        # SSL/TLS Checker
        if args.ssl_check:
            log_info("=== Starting SSL/TLS Check ===")
            ssl_check = SSLChecker(args.target, args.verbose)
            results["ssl_check"] = ssl_check.run()
        
        # Brute Force
        if args.bruteforce:
            from modules.scan.bruteforce import BruteForce
            log_info("=== Starting Brute Force ===")
            bf = BruteForce(
                target=args.target,
                port=args.ports.split(',')[0] if ',' in args.ports else args.ports,
                service=args.service,
                userlist=args.userlist,
                passlist=args.passlist,
                threads=args.threads,
                verbose=args.verbose
            )
            results["bruteforce"] = bf.run()
        
        # Save results
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log_success(f"Results saved to {args.output}")
        
        # Generate HTML report
        if args.report:
            from modules.reporting.html_report import HTMLReport
            report_name = args.output.replace('.json', '.html')
            report = HTMLReport(args.output, report_name)
            report.generate()
        
        log_info("Dragon Eye - Scan completed. Stay secure!")

if __name__ == "__main__":
    main()
