"""
GOODS-DRAGON Smart Orchestrator v2
Integrates with professional tools: subfinder, nuclei, httpx
"""
import subprocess
import json
import os
from datetime import datetime

class Orchestrator:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = {}
    
    def check_tool(self, tool):
        """Check if a tool is installed."""
        try:
            subprocess.run(["which", tool], capture_output=True, text=True, timeout=5)
            return True
        except:
            return False
    
    def run_subfinder(self):
        """Run subfinder for subdomain enumeration."""
        if not self.check_tool("subfinder"):
            print("[!] Subfinder not installed. Install with: pkg install subfinder")
            return 0
        
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target, "-silent"],
                capture_output=True, text=True, timeout=120
            )
            subdomains = [s for s in result.stdout.strip().split('\n') if s]
            self.results['subdomains'] = subdomains
            return len(subdomains)
        except:
            return 0
    
    def run_httpx(self):
        """Run httpx to probe alive subdomains."""
        if not self.check_tool("httpx"):
            print("[!] Httpx not installed. Install with: pkg install httpx")
            return 0
        
        subs = self.results.get('subdomains', [self.target])
        targets_file = f"reports/{self.target}_targets.txt"
        os.makedirs("reports", exist_ok=True)
        
        with open(targets_file, 'w') as f:
            f.write('\n'.join(subs))
        
        try:
            result = subprocess.run(
                ["httpx", "-l", targets_file, "-silent", "-status-code", "-title", "-tech-detect"],
                capture_output=True, text=True, timeout=120
            )
            alive = [line for line in result.stdout.strip().split('\n') if line]
            self.results['alive_hosts'] = alive
            return len(alive)
        except:
            return 0
    
    def run_nuclei(self):
        """Run nuclei on alive hosts."""
        if not self.check_tool("nuclei"):
            print("[!] Nuclei not installed. Install with: pkg install nuclei")
            return 0
        
        subs = self.results.get('subdomains', [self.target])
        targets_file = f"reports/{self.target}_targets.txt"
        os.makedirs("reports", exist_ok=True)
        
        with open(targets_file, 'w') as f:
            f.write('\n'.join(subs))
        
        try:
            result = subprocess.run(
                ["nuclei", "-l", targets_file, "-severity", "critical,high,medium",
                 "-silent", "-json"],
                capture_output=True, text=True, timeout=300
            )
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    findings.append(json.loads(line))
            self.results['nuclei_findings'] = findings
            return len(findings)
        except:
            return 0
    
    def generate_hackerone_report(self):
        """Generate HackerOne-style report."""
        report = []
        report.append("# 🐉 GOODS-DRAGON Automated Pentest Report")
        report.append(f"**Target:** {self.target}")
        report.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Tool:** GOODS-DRAGON v2.0.0 Orchestrator")
        report.append("---")
        
        # Executive Summary
        report.append("## 📋 Executive Summary")
        sub_count = len(self.results.get('subdomains', []))
        alive_count = len(self.results.get('alive_hosts', []))
        vuln_count = len(self.results.get('nuclei_findings', []))
        report.append(f"- Discovered: {sub_count} subdomains")
        report.append(f"- Alive: {alive_count} hosts")
        report.append(f"- Vulnerabilities: {vuln_count}")
        
        # Subdomains
        report.append("\n## 🌐 Discovered Subdomains")
        for sub in self.results.get('subdomains', []):
            report.append(f"- {sub}")
        
        # Alive Hosts
        if self.results.get('alive_hosts'):
            report.append("\n## 🟢 Alive Hosts")
            for host in self.results['alive_hosts']:
                report.append(f"- {host}")
        
        # Vulnerabilities
        if self.results.get('nuclei_findings'):
            report.append("\n## 🔥 Vulnerability Findings")
            for finding in self.results['nuclei_findings']:
                info = finding.get('info', {})
                report.append(f"### {info.get('name', 'Unknown')}")
                report.append(f"- **Severity:** {info.get('severity', 'N/A')}")
                report.append(f"- **URL:** {finding.get('matched-at', 'N/A')}")
                report.append(f"- **Description:** {info.get('description', 'N/A')}")
                if info.get('remediation'):
                    report.append(f"- **Remediation:** {info['remediation']}")
                report.append("")
        
        report.append("---")
        report.append("*Report generated by GOODS-DRAGON Orchestrator*")
        report.append("*Team: L-DRAGON | Owner: 0xL-DRAGON*")
        return '\n'.join(report)
    
    def run(self):
        """Execute full orchestration workflow."""
        print("🐉 Starting GOODS-DRAGON Orchestrator v2...")
        print(f"Target: {self.target}\n")
        
        # Step 1: Subfinder
        print("[1/4] Running Subfinder...")
        sub_count = self.run_subfinder()
        print(f"  ✅ Found {sub_count} subdomains")
        
        # Step 2: Httpx
        print("[2/4] Running Httpx (probing alive hosts)...")
        alive_count = self.run_httpx()
        print(f"  ✅ Found {alive_count} alive hosts")
        
        # Step 3: Nuclei
        print("[3/4] Running Nuclei (vulnerability scan)...")
        vuln_count = self.run_nuclei()
        print(f"  ✅ Found {vuln_count} vulnerabilities")
        
        # Step 4: Report
        print("[4/4] Generating HackerOne report...")
        report = self.generate_hackerone_report()
        report_file = f"reports/{self.target}_hackerone_report.md"
        os.makedirs("reports", exist_ok=True)
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"\n✅ Report saved: {report_file}")
        return report
