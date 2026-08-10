"""
GOODS-DRAGON Nmap Wrapper
Integrates Nmap for professional port scanning.
"""
import subprocess
import json
import re
import os

class NmapScanner:
    def __init__(self, target, ports="80,443,8080,8443,3000,5000,8000,9090", threads=50, verbose=False):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.verbose = verbose
    
    def scan(self):
        """Run Nmap and parse results."""
        try:
            cmd = [
                "nmap",
                "-p", self.ports,
                "-sV",                    # Service/version detection
                "-sC",                    # Default scripts
                "-T4",                    # Aggressive timing
                "--open",                 # Only show open ports
                "-oX", "-",              # XML output to stdout
                self.target
            ]
            
            if self.verbose:
                print(f"  Running: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout)
        except FileNotFoundError:
            print("  [!] Nmap not installed. Run: pkg install nmap")
            return []
        except Exception as e:
            print(f"  [!] Nmap error: {e}")
            return []
    
    def _parse_nmap_xml(self, xml_output):
        """Parse Nmap XML output."""
        findings = []
        
        # Extract open ports with service info
        for match in re.finditer(r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="open"/>.*?<service name="([^"]*)"(?: product="([^"]*)" version="([^"]*)")?.*?</port>', xml_output, re.DOTALL):
            findings.append({
                'port': match.group(2),
                'protocol': match.group(1),
                'service': match.group(3),
                'product': match.group(4) or '',
                'version': match.group(5) or ''
            })
        
        # Extract OS detection if available
        os_match = re.search(r'<osmatch name="([^"]*)" accuracy="(\d+)"', xml_output)
        if os_match:
            findings.append({
                'type': 'os_detection',
                'os': os_match.group(1),
                'accuracy': os_match.group(2)
            })
        
        return findings
    
    def run(self):
        """Execute Nmap scan."""
        if self.verbose:
            print(f"  🔍 Nmap scanning {self.target}...")
        
        results = self.scan()
        
        if results:
            open_ports = [r for r in results if 'port' in r]
            if self.verbose:
                for p in open_ports:
                    print(f"  ✅ {p['port']}/{p['protocol']} - {p['service']} {p['product']} {p['version']}")
                print(f"  ✅ Found {len(open_ports)} open ports")
        
        return results
