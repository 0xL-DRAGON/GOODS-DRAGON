"""
GOODS-DRAGON SQLMap Wrapper
Integrates SQLMap for professional SQL injection testing.
"""
import subprocess
import re
import os

class SQLMapScanner:
    def __init__(self, target, params=None, verbose=False):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.params = params or []
        self.verbose = verbose
    
    def scan(self):
        """Run SQLMap and parse results."""
        try:
            cmd = [
                "sqlmap",
                "-u", self.target,
                "--batch",               # Non-interactive
                "--random-agent",        # Random User-Agent
                "--level", "2",          # Medium testing level
                "--risk", "2",           # Medium risk
                "--threads", "4",        # 4 threads
                "--output-dir", "reports/sqlmap",  # Output directory
                "--forms",               # Test forms
                "--crawl", "2"           # Crawl 2 levels deep
            ]
            
            # Add specific parameters if known
            if self.params:
                for param in self.params:
                    cmd.extend(["-p", param])
            
            if self.verbose:
                print(f"  Running SQLMap on {self.target}...")
                print(f"  This may take several minutes...")
            
            os.makedirs("reports/sqlmap", exist_ok=True)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return self._parse_sqlmap_output(result.stdout + result.stderr)
        
        except FileNotFoundError:
            print("  [!] SQLMap not installed. Run: pip install sqlmap")
            return []
        except subprocess.TimeoutExpired:
            print("  [!] SQLMap timed out after 10 minutes")
            return []
        except Exception as e:
            print(f"  [!] SQLMap error: {e}")
            return []
    
    def _parse_sqlmap_output(self, output):
        """Parse SQLMap output for vulnerabilities."""
        findings = []
        
        # Check for successful injection
        if "is vulnerable" in output.lower() or "payload:" in output.lower():
            # Extract the vulnerable parameter and type
            param_match = re.search(r"Parameter '([^']+)'.*?is vulnerable", output, re.IGNORECASE)
            type_match = re.search(r"Type: (.*?)(?:\n|$)", output)
            title_match = re.search(r"Title: (.*?)(?:\n|$)", output)
            payload_match = re.search(r"Payload: (.*?)(?:\n|$)", output)
            
            findings.append({
                'type': 'SQL Injection',
                'severity': 'CRITICAL',
                'parameter': param_match.group(1) if param_match else 'unknown',
                'injection_type': type_match.group(1).strip() if type_match else 'unknown',
                'title': title_match.group(1).strip() if title_match else 'SQL Injection found',
                'payload': payload_match.group(1).strip() if payload_match else 'See SQLMap output',
                'url': self.target
            })
        
        # Check for database fingerprinting
        db_match = re.search(r"back-end DBMS: (.*?)(?:\n|$)", output)
        if db_match:
            findings.append({
                'type': 'Database Fingerprint',
                'severity': 'INFO',
                'database': db_match.group(1).strip(),
                'url': self.target
            })
        
        return findings
    
    def run(self):
        """Execute SQLMap scan."""
        if self.verbose:
            print(f"  💉 SQLMap testing {self.target}...")
        
        results = self.scan()
        
        if results:
            vulns = [r for r in results if r.get('severity') == 'CRITICAL']
            if self.verbose:
                for v in vulns:
                    print(f"  🔥 {v['type']} on parameter '{v['parameter']}' ({v['injection_type']})")
                    print(f"     Payload: {v['payload'][:80]}...")
                if vulns:
                    print(f"  ✅ Found {len(vulns)} SQL injection(s)!")
                else:
                    print(f"  ℹ️ No SQL injection found, but database info collected")
        
        return results
