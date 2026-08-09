"""
GOODS-DRAGON Smart Compound Attack Engine
Automatically chains vulnerabilities for maximum impact.
"""
import json, os, re
from datetime import datetime

class SmartEngine:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.findings = {}
        self.chains = []

    def load_scan_results(self, report_dir="reports"):
        """Load all previous scan results for the target."""
        for fname in os.listdir(report_dir):
            if fname.endswith(".json"):
                with open(os.path.join(report_dir, fname), "r") as f:
                    data = json.load(f)
                    self.findings[fname] = data

    def analyze_and_chain(self):
        """Look for dangerous combinations."""
        # Rule 1: Subdomain takeover + outdated tech
        if "recon" in str(self.findings):
            for key in self.findings:
                if "subdomain" in key.lower():
                    subs = self.findings[key].get("subdomains", [])
                    for sub in subs:
                        if "dev" in sub or "staging" in sub or "test" in sub:
                            self.chains.append({
                                "type": "Potential Takeover + Legacy Tech",
                                "target": sub,
                                "risk": "Critical",
                                "action": "Check for outdated CMS/CVE on this subdomain"
                            })

        # Rule 2: SQLi + login page
        has_sqli = any("sqli" in str(v).lower() for v in self.findings.values())
        has_login = any("login" in str(v).lower() for v in self.findings.values())
        if has_sqli and has_login:
            self.chains.append({
                "type": "SQLi → Credential Theft",
                "target": self.target,
                "risk": "Critical",
                "action": "Use SQLi to extract admin credentials from login form"
            })

        # Rule 3: Open redirect + phishing
        has_redirect = any("open.redirect" in str(v).lower() for v in self.findings.values())
        has_email = any("email" in str(v).lower() for v in self.findings.values())
        if has_redirect and has_email:
            self.chains.append({
                "type": "Open Redirect → Phishing Campaign",
                "target": self.target,
                "risk": "High",
                "action": "Craft phishing email using discovered emails + open redirect"
            })

    def generate_report(self):
        """Generate a human-readable attack chain report."""
        if not self.chains:
            return "No attack chains found. Run more scans first."
        
        report = []
        report.append("=" * 60)
        report.append("🐉 SMART COMPOUND ATTACK REPORT")
        report.append(f"Target: {self.target}")
        report.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        for i, chain in enumerate(self.chains, 1):
            report.append(f"\n[CHAIN {i}] {chain['type']}")
            report.append(f"  Risk: {chain['risk']}")
            report.append(f"  Target: {chain['target']}")
            report.append(f"  Action: {chain['action']}")
        
        report.append("\n" + "=" * 60)
        report.append("These chains can be exploited for maximum impact.")
        report.append("Team: L-DRAGON | Owner: 0xL-DRAGON")
        return "\n".join(report)

    def run(self):
        """Execute the smart engine."""
        self.load_scan_results()
        self.analyze_and_chain()
        return self.generate_report()
