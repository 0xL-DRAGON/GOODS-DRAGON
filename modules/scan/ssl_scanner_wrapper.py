"""
GOODS-DRAGON SSL/TLS Scanner Wrapper
Integrates testssl.sh for professional SSL analysis.
"""
import subprocess
import re

class SSLScanner:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
    
    def scan(self):
        """Run testssl.sh and parse results."""
        try:
            cmd = [
                "testssl",
                "--quiet",
                "--color", "0",
                self.target
            ]
            
            if self.verbose:
                print(f"  Running testssl.sh on {self.target}...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return self._parse_testssl(result.stdout)
        
        except FileNotFoundError:
            if self.verbose:
                print("  [!] testssl.sh not installed")
            return []
        except Exception as e:
            if self.verbose:
                print(f"  [!] testssl error: {e}")
            return []
    
    def _parse_testssl(self, output):
        """Parse testssl.sh output."""
        findings = []
        
        # Find vulnerabilities
        vulns = re.findall(r'(NOT ok|WARN|VULNERABLE)\s+(.*)', output)
        for status, description in vulns:
            findings.append({
                'type': 'SSL/TLS',
                'severity': 'HIGH' if 'VULNERABLE' in status else 'MEDIUM',
                'description': description.strip(),
                'status': status.strip()
            })
        
        # Extract grade if available
        grade = re.search(r'Grade\s+([A-F][+-]?)', output)
        if grade:
            findings.append({
                'type': 'SSL Grade',
                'severity': 'INFO',
                'grade': grade.group(1)
            })
        
        return findings
    
    def run(self):
        """Execute SSL scan."""
        if self.verbose:
            print(f"  🔒 SSL scanning {self.target}...")
        
        results = self.scan()
        
        if self.verbose:
            vulns = [r for r in results if r['type'] == 'SSL/TLS']
            if vulns:
                for v in vulns:
                    print(f"  ⚠️  [{v['severity']}] {v['description']}")
            else:
                print(f"  ✅ SSL configuration looks good")
        
        return results
