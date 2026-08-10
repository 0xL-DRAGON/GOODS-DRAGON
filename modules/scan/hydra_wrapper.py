"""
GOODS-DRAGON Hydra Wrapper
"""
import subprocess

class HydraScanner:
    def __init__(self, target, service="ssh", userlist="admin,root", passlist="password,123456", threads=4, verbose=False):
        self.target = target
        self.service = service
        self.userlist = userlist
        self.passlist = passlist
        self.threads = threads
        self.verbose = verbose
    
    def scan(self):
        try:
            cmd = ["hydra", "-L", "/dev/stdin", "-P", "/dev/stdin", 
                   f"{self.service}://{self.target}", "-t", str(self.threads), "-f", "-V"]
            result = subprocess.run(cmd, input=f"{self.userlist}\n{self.passlist}", 
                                   capture_output=True, text=True, timeout=120)
            findings = []
            for match in re.finditer(r'login: (\S+)\s+password: (\S+)', result.stdout):
                findings.append({'service': self.service, 'username': match.group(1), 'password': match.group(2)})
            return findings
        except:
            return []
    
    def run(self):
        if self.verbose:
            print(f"  🔨 Hydra brute forcing {self.service}://{self.target}...")
        results = self.scan()
        if self.verbose:
            for r in results:
                print(f"  🔥 Found: {r['username']}:{r['password']}")
        return results
