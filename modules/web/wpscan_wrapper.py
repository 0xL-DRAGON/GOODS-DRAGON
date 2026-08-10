"""
GOODS-DRAGON WPScan Wrapper
"""
import subprocess
import re

class WPScanScanner:
    def __init__(self, target, verbose=False):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.verbose = verbose
    
    def scan(self):
        try:
            cmd = ["wpscan", "--url", self.target, "--format", "json", "--no-banner", "--random-user-agent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            findings = []
            if "vulnerable" in result.stdout.lower() or "version" in result.stdout.lower():
                findings.append({'type': 'WordPress Info', 'severity': 'INFO', 'data': result.stdout[:500]})
            return findings
        except:
            return []
    
    def run(self):
        if self.verbose:
            print(f"  🔍 WPScan testing {self.target}...")
        results = self.scan()
        if self.verbose:
            print(f"  ✅ WPScan found {len(results)} items")
        return results
