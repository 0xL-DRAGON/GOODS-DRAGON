"""
GOODS-DRAGON Self-Contained Orchestrator
Uses internal modules—no external dependencies.
"""
import json
import os
from datetime import datetime
from modules.recon.subdomain import SubdomainFinder
from modules.web.tech_detect import TechnologyDetector
from modules.web.headers_check import SecurityHeadersChecker
from modules.web.secret_scanner import SecretScanner
from modules.scan.portscan import PortScanner
from core.logger import log_info, log_success, log_warning

class Orchestrator:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = {}
    
    def run_subdomain_enum(self):
        """Run internal SubdomainFinder."""
        log_info("Running Subdomain Enumeration...")
        finder = SubdomainFinder(
            domain=self.target,
            wordlist_path="wordlists/subdomains.txt",
            threads=50,
            verbose=self.verbose
        )
        result = finder.run()
        self.results['subdomains'] = result.get('subdomains', [])
        self.results['alive'] = result.get('alive', [])
        return len(self.results['alive'])
    
    def run_port_scan(self):
        """Run internal PortScanner."""
        log_info("Running Port Scan...")
        scanner = PortScanner(
            target=self.target,
            ports="80,443,8080,8443,3000,5000,8000,9090",
            threads=50,
            verbose=self.verbose,
            banner=True
        )
        self.results['ports'] = scanner.run()
        return len(self.results.get('ports', {}).get('open', []))
    
    def run_tech_detect(self):
        """Run internal TechnologyDetector."""
        log_info("Running Technology Detection...")
        detector = TechnologyDetector(
            target=f"https://{self.target}" if not self.target.startswith('http') else self.target,
            verbose=self.verbose
        )
        self.results['technologies'] = detector.run()
        return len(self.results.get('technologies', {}).get('technologies', []))
    
    def run_headers_check(self):
        """Run internal SecurityHeadersChecker."""
        log_info("Checking Security Headers...")
        checker = SecurityHeadersChecker(
            target=f"https://{self.target}" if not self.target.startswith('http') else self.target,
            verbose=self.verbose
        )
        self.results['headers'] = checker.run()
        return self.results.get('headers', {})
    
    def run_secret_scan(self):
        """Run internal SecretScanner."""
        log_info("Scanning for Secrets...")
        scanner = SecretScanner(
            target=f"https://{self.target}" if not self.target.startswith('http') else self.target,
            verbose=self.verbose
        )
        self.results['secrets'] = scanner.run()
        return len(self.results.get('secrets', {}).get('findings', []))
    
    def generate_hackerone_report(self):
        """Generate complete HackerOne-style report."""
        report = []
        report.append("# 🐉 GOODS-DRAGON Self-Contained Pentest Report")
        report.append(f"**Target:** {self.target}")
        report.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Tool:** GOODS-DRAGON v2.0.0 (All Internal Modules)")
        report.append("---")
        
        # Executive Summary
        report.append("## 📋 Executive Summary")
        subdomains = self.results.get('subdomains', [])
        alive = [s for s in subdomains if s.get('alive')]
        ports = self.results.get('ports', {}).get('open', [])
        techs = self.results.get('technologies', {}).get('technologies', [])
        secrets = self.results.get('secrets', {}).get('findings', [])
        
        report.append(f"- **Subdomains Discovered:** {len(alive)}")
        report.append(f"- **Open Ports:** {len(ports)}")
        report.append(f"- **Technologies Detected:** {len(techs)}")
        report.append(f"- **Secrets Found:** {len(secrets)}")
        
        # Detailed Findings
        if ports:
            report.append("\n## 🌐 Open Ports")
            for port in ports:
                report.append(f"- **{port.get('port')}/{port.get('protocol', 'tcp')}** {port.get('service', '')} {port.get('banner', '')}")
        
        if techs:
            report.append("\n## 🔧 Technologies Detected")
            for tech in techs:
                report.append(f"- **{tech.get('name', 'Unknown')}** ({tech.get('type', 'N/A')})")
        
        if secrets:
            report.append("\n## 🔥 Secrets Found")
            for secret in secrets:
                report.append(f"- **{secret.get('type', 'Unknown')}** at {secret.get('url', 'N/A')}")
        
        # Subdomains
        if alive:
            report.append("\n## 🌍 Active Subdomains")
            for sub in alive:
                report.append(f"- **{sub.get('subdomain', '?')}** → {sub.get('url', '?')} [{sub.get('status', '?')}]")
        
        # Security Headers
        headers = self.results.get('headers', {})
        if headers:
            present = headers.get('present', [])
            missing = headers.get('missing', [])
            report.append(f"\n## 🛡️ Security Headers ({len(present)}/{len(present)+len(missing)} present)")
            for h in missing:
                report.append(f"- ❌ {h.get('name', '?')} missing")
            for h in present:
                report.append(f"- ✅ {h.get('name', '?')}: {h.get('value', '?')}")
        
        report.append("\n---")
        report.append("*Report generated by GOODS-DRAGON Self-Contained Orchestrator*")
        report.append("*Team: L-DRAGON | Owner: 0xL-DRAGON*")
        return '\n'.join(report)
    
    def _deduplicate(self, items, key='subdomain'):
        """Remove duplicate entries from results."""
        seen = set()
        unique = []
        for item in items:
            if isinstance(item, dict):
                val = item.get(key, str(item))
            else:
                val = str(item)
            if val not in seen:
                seen.add(val)
                unique.append(item)
        return unique
    
    def export_json(self):
        """Export results as standardized JSON."""
        import json
        json_file = f"reports/{self.target}_results.json"
        os.makedirs("reports", exist_ok=True)
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        return json_file
    
    def _calculate_cvss(self, findings):
        """Calculate overall CVSS score based on findings."""
        if not findings:
            return "0.0 (No vulnerabilities)"
        severity_scores = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.5, 'LOW': 3.0}
        max_score = 0
        for f in findings:
            sev = f.get('info', {}).get('severity', 'low').upper()
            score = severity_scores.get(sev, 1.0)
            max_score = max(max_score, score)
        level = 'CRITICAL' if max_score >= 9 else 'HIGH' if max_score >= 7 else 'MEDIUM' if max_score >= 4 else 'LOW'
        return f"{max_score} ({level})"
    
    def run(self):
        """Execute full self-contained orchestration."""
        print("🐉 GOODS-DRAGON Self-Contained Orchestrator")
        print(f"Target: {self.target}")
        print("=" * 50)
        
        # Step 1: Subdomain Enumeration
        print("\n[1/7] Spider Crawling (finding URLs & parameters)...")
        from modules.recon.spider import Spider
        spider = Spider(self.target, max_pages=30, verbose=self.verbose)
        spider_results = spider.run()
        self.results['spider'] = spider_results
        if spider_results['params']:
            print(f"  📋 Parameters found: {', '.join(spider_results['params'][:10])}")
        
        print("\n[2/7] Subdomain Enumeration...")
        alive_count = self.run_subdomain_enum()
        print(f"  ✅ Found {alive_count} active subdomains")
        
        # Step 2: Port Scan
        print("\n[3/7] Port Scanning...")
        port_count = self.run_port_scan()
        print(f"  ✅ Found {port_count} open ports")
        
        # Step 3: Technology Detection
        print("\n[4/7] Technology Detection...")
        tech_count = self.run_tech_detect()
        print(f"  ✅ Detected {tech_count} technologies")
        
        # Step 4: Security Headers
        print("\n[5/7] Security Headers Check...")
        self.run_headers_check()
        print(f"  ✅ Headers analyzed")
        
        # Step 5: Secret Scan
        print("\n[6/7] Secret Scanning...")
        secret_count = self.run_secret_scan()
        print(f"  ✅ Found {secret_count} potential secrets")
        
        # Deduplicate results
        if self.results.get('subdomains'):
            self.results['subdomains'] = self._deduplicate(self.results['subdomains'], 'subdomain')
        
        # Generate Report
        print("\n📄 Generating HackerOne Report...")
        report = self.generate_hackerone_report()
        report_file = f"reports/{self.target}_full_report.md"
        os.makedirs("reports", exist_ok=True)
        with open(report_file, 'w') as f:
            f.write(report)
        
        json_file = self.export_json()
        print(f"✅ Full report saved: {report_file}")
        print(f"✅ JSON results saved: {json_file}")
        return report
