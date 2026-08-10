"""
GOODS-DRAGON Nmap Wrapper
Integrates Nmap for professional port scanning.
"""
import subprocess
import re

class NmapScanner:
    def __init__(self, target, ports="80,443,8080,8443,3000,5000,8000,9090", threads=50, verbose=False):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.verbose = verbose
    
    def scan(self):
        """Run Nmap and parse text output."""
        try:
            cmd = [
                "nmap",
                "-p", self.ports,
                "-sV",
                "-sC",
                "-T4",
                self.target
            ]
            
            if self.verbose:
                print(f"  Running: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_text(result.stdout)
        except FileNotFoundError:
            print("  [!] Nmap not installed. Run: pkg install nmap")
            return []
        except Exception as e:
            print(f"  [!] Nmap error: {e}")
            return []
    
    def _parse_nmap_text(self, output):
        """Parse Nmap text output."""
        findings = []
        
        # Parse lines like: 80/tcp  open  http     OpenResty web app server
        for match in re.finditer(r'(\d+)/(\w+)\s+(\w+)\s+(\S+)\s+(.*)', output):
            port, protocol, state, service, version = match.groups()
            if state == 'open':
                findings.append({
                    'port': port,
                    'protocol': protocol,
                    'state': state,
                    'service': service,
                    'version': version.strip()
                })
        
        return findings
    
    def run(self):
        """Execute Nmap scan."""
        if self.verbose:
            print(f"  🔍 Nmap scanning {self.target}...")
        
        results = self.scan()
        
        if results:
            if self.verbose:
                for p in results:
                    print(f"  ✅ {p['port']}/{p['protocol']} - {p['service']} {p['version']}")
                print(f"  ✅ Found {len(results)} open ports")
        
        return results
