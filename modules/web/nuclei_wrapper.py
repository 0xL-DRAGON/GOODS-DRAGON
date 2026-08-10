"""
GOODS-DRAGON Nuclei Wrapper
Integrates Nuclei for professional vulnerability scanning.
"""
import subprocess
import json
import os

class NucleiScanner:
    def __init__(self, target, severity="critical,high,medium", verbose=False):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.severity = severity
        self.verbose = verbose
    
    def scan(self):
        """Run Nuclei and parse results."""
        try:
            cmd = [
                "nuclei",
                "-u", self.target,
                "-severity", self.severity,
                "-silent",
                "-json",
                "-stats",
                "-timeout", "30"
            ]
            
            if self.verbose:
                print(f"  Running Nuclei on {self.target}...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except:
                        pass
            
            return findings
        
        except FileNotFoundError:
            print("  [!] Nuclei not installed")
            return []
        except Exception as e:
            print(f"  [!] Nuclei error: {e}")
            return []
    
    def run(self):
        """Execute Nuclei scan."""
        if self.verbose:
            print(f"  🧬 Nuclei scanning {self.target}...")
        
        results = self.scan()
        
        if results:
            if self.verbose:
                for r in results:
                    info = r.get('info', {})
                    sev = info.get('severity', 'unknown').upper()
                    print(f"  🔥 [{sev}] {info.get('name', 'Unknown')}")
            print(f"  ✅ Found {len(results)} vulnerabilities")
        
        return results
