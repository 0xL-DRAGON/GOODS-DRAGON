"""
GOODS-DRAGON JWT Scanner Wrapper
Integrates jwt_tool for professional JWT analysis.
"""
import subprocess, re

class JWTScanner:
    def __init__(self, target, token=None, verbose=False):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.token = token
        self.verbose = verbose
    def scan(self):
        try:
            cmd = ["jwt_tool", self.target]
            if self.token: cmd.extend(["-t", self.token])
            cmd.extend(["--no-logo", "-M", "at"])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            findings = []
            if "VULNERABLE" in result.stdout or "exploit" in result.stdout.lower():
                findings.append({'type': 'JWT', 'severity': 'HIGH', 'data': result.stdout[:500]})
            return findings
        except:
            return []
    def run(self):
        if self.verbose: print(f"  🔐 JWT scanning {self.target}...")
        results = self.scan()
        if self.verbose:
            print(f"  ✅ Found {len(results)} JWT issues") if results else print(f"  ✅ No JWT issues")
        return results
