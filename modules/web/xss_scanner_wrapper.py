"""
GOODS-DRAGON XSS Scanner Wrapper
Integrates dalfox for professional XSS scanning.
"""
import subprocess
import json
import os

class XSSScanner:
    def __init__(self, target, verbose=False):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.verbose = verbose
    
    def scan(self):
        """Run dalfox and parse results."""
        try:
            cmd = [
                "dalfox", "url", self.target,
                "--silence",
                "--format", "json",
                "--waf-evasion",
                "--skip-bav",
                "--skip-mining-all",
                "--timeout", "10"
            ]
            
            if self.verbose:
                print(f"  Running dalfox on {self.target}...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line and line.startswith('{'):
                    try:
                        finding = json.loads(line)
                        findings.append({
                            'type': 'XSS',
                            'severity': 'HIGH',
                            'payload': finding.get('payload', 'unknown'),
                            'param': finding.get('param', 'unknown'),
                            'method': finding.get('method', 'GET'),
                            'url': self.target
                        })
                    except:
                        pass
            
            return findings
        
        except FileNotFoundError:
            if self.verbose:
                print("  [!] dalfox not installed. Run: pkg install dalfox")
            return []
        except Exception as e:
            if self.verbose:
                print(f"  [!] dalfox error: {e}")
            return []
    
    def run(self):
        """Execute XSS scan."""
        if self.verbose:
            print(f"  🎯 XSS scanning {self.target}...")
        
        results = self.scan()
        
        if self.verbose:
            if results:
                for r in results:
                    print(f"  🔥 XSS found on param '{r['param']}' via {r['method']}")
                    print(f"     Payload: {r['payload'][:60]}...")
                print(f"  ✅ Found {len(results)} XSS vulnerabilities")
            else:
                print(f"  ✅ No XSS found")
        
        return results
