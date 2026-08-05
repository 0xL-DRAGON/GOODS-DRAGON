#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
from datetime import datetime
from core.logger import log_info, log_success, log_warning, log_error

class AutoScanner:
    def __init__(self, target, verbose=False, threads=30, output="reports/auto_scan.json"):
        self.target = target
        self.verbose = verbose
        self.threads = threads
        self.output = output
        self.results = {}
        self.start_time = datetime.now()

    def run_recon(self):
        """Run all recon modules"""
        log_info("=== Starting Reconnaissance Phase ===")
        
        # Subdomain Enumeration
        from modules.recon.subdomain import SubdomainFinder
        finder = SubdomainFinder(
            domain=self.target,
            wordlist_path="wordlists/subdomains.txt",
            threads=self.threads,
            verbose=self.verbose
        )
        self.results["subdomains"] = finder.run()
        
        # Active Subdomain Scan
        from modules.recon.active_scan import ActiveSubdomainScanner
        active = ActiveSubdomainScanner(
            self.target, "wordlists/subdomains.txt", self.threads, self.verbose
        )
        self.results["active_scan"] = active.run()
        
        # Wayback URLs
        from modules.recon.wayback import WaybackScanner
        wayback = WaybackScanner(self.target, self.verbose)
        self.results["wayback"] = wayback.run()
        
        # Takeover Check
        from modules.recon.takeover import SubdomainTakeover
        sub_list = self.results.get("subdomains", {}).get("subdomains", [])
        if sub_list:
            sub_names = [s.get("subdomain", "") for s in sub_list if s.get("subdomain")]
            if sub_names:
                takeover = SubdomainTakeover(sub_names, self.verbose)
                self.results["takeover"] = takeover.run()
        
        # Cloud Enumeration
        from modules.recon.cloud_enum import CloudEnum
        cloud = CloudEnum(self.target, self.threads, self.verbose)
        self.results["cloud_enum"] = cloud.run()

    def run_web(self):
        """Run all web modules"""
        log_info("=== Starting Web Vulnerabilities Phase ===")
        target_url = f"http://{self.target}" if not self.target.startswith("http") else self.target
        
        # SQL Injection
        from modules.web.sqli import SQLiScanner
        sqli = SQLiScanner(f"{target_url}?id=1", self.verbose)  # Use a common param
        self.results["sqli"] = sqli.run()
        
        # XSS
        from modules.web.xss import XSSScanner
        xss = XSSScanner(f"{target_url}?q=test", self.verbose, self.threads)
        self.results["xss"] = xss.run()
        
        # CMS Detection
        from modules.web.cms import CMSDetector
        cms = CMSDetector(target_url, self.verbose)
        self.results["cms"] = cms.run()
        
        # Technology Detection
        from modules.web.tech_detect import TechnologyDetector
        tech = TechnologyDetector(target_url, self.verbose)
        self.results["tech_detect"] = tech.run()
        
        # Security Headers
        from modules.web.headers_check import SecurityHeadersChecker
        headers = SecurityHeadersChecker(target_url, self.verbose)
        self.results["headers_check"] = headers.run()
        
        # Git Scan
        from modules.web.git_scan import GitScanner
        git = GitScanner(target_url, self.verbose)
        self.results["git_scan"] = git.run()
        
        # WAF Detection
        from modules.web.waf_detect import WAFDetector
        waf = WAFDetector(target_url, self.verbose)
        self.results["waf_detect"] = waf.run()
        
        # CORS Check
        from modules.web.cors import CORSChecker
        cors = CORSChecker(target_url, self.verbose)
        self.results["cors"] = cors.run()
        
        # Directory Bruteforce
        from modules.web.dir_bruteforce import DirBruteforce
        dir_bf = DirBruteforce(target_url, "wordlists/dirs.txt", self.threads, self.verbose)
        self.results["dir_bruteforce"] = dir_bf.run()
        
        # Parameter Discovery
        from modules.web.param_discovery import ParameterDiscovery
        param = ParameterDiscovery(target_url, self.verbose)
        self.results["param_discovery"] = param.run()

    def run_scan(self):
        """Run all scan modules"""
        log_info("=== Starting Network Scan Phase ===")
        
        # Port Scan
        from modules.scan.portscan import PortScanner
        scanner = PortScanner(
            target=self.target,
            ports="21,22,23,25,80,443,3306,3389,8080",
            threads=self.threads,
            verbose=self.verbose,
            banner=True
        )
        self.results["port_scan"] = scanner.run()
        
        # SSL Check
        from modules.scan.ssl_check import SSLChecker
        ssl = SSLChecker(self.target, self.verbose)
        self.results["ssl_check"] = ssl.run()

    def generate_report(self):
        """Generate a comprehensive report"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        report = {
            "target": self.target,
            "scan_date": self.start_time.isoformat(),
            "duration": elapsed,
            "results": self.results
        }
        
        with open(self.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        log_success(f"Auto-scan report saved to {self.output}")

    def run(self):
        log_info(f"🐉 GOODS-DRAGON Auto-Scanner started on: {self.target}")
        log_info(f"Threads: {self.threads} | Verbose: {self.verbose}")
        
        try:
            self.run_recon()
            self.run_web()
            self.run_scan()
            self.generate_report()
            
            # Print summary
            log_success("=" * 50)
            log_success("AUTO-SCAN COMPLETED")
            log_success(f"Total modules run: {len(self.results)}")
            log_success(f"Duration: {int((datetime.now() - self.start_time).total_seconds())} seconds")
            log_success(f"Report: {self.output}")
            log_success("=" * 50)
        except Exception as e:
            log_error(f"Auto-scan failed: {e}")

        return self.results
