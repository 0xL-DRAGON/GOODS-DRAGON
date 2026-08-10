"""
GOODS-DRAGON Subdomain Discovery Wrapper
Integrates Subfinder + Amass + Internal Wordlist for comprehensive enumeration.
"""
import subprocess
import os

class SubdomainDiscovery:
    def __init__(self, target, wordlist="wordlists/subdomains.txt", threads=30, verbose=False):
        self.target = target
        self.wordlist = wordlist
        self.threads = threads
        self.verbose = verbose
        self.subdomains = set()
    
    def run_subfinder(self):
        """Run Subfinder for passive enumeration."""
        try:
            cmd = ["subfinder", "-d", self.target, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            subs = [s.strip() for s in result.stdout.split('\n') if s.strip()]
            if self.verbose:
                print(f"  Subfinder: {len(subs)} found")
            return subs
        except FileNotFoundError:
            if self.verbose:
                print("  [!] Subfinder not installed")
            return []
        except Exception as e:
            if self.verbose:
                print(f"  [!] Subfinder error: {e}")
            return []
    
    def run_amass(self):
        """Run Amass for deep enumeration."""
        try:
            cmd = ["amass", "enum", "-passive", "-d", self.target, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            subs = [s.strip() for s in result.stdout.split('\n') if s.strip()]
            if self.verbose:
                print(f"  Amass: {len(subs)} found")
            return subs
        except FileNotFoundError:
            if self.verbose:
                print("  [!] Amass not installed")
            return []
        except Exception as e:
            if self.verbose:
                print(f"  [!] Amass error: {e}")
            return []
    
    def run_bruteforce(self):
        """Run internal wordlist brute force as fallback."""
        try:
            from modules.recon.subdomain import SubdomainFinder
            finder = SubdomainFinder(
                domain=self.target,
                wordlist_path=self.wordlist,
                threads=self.threads,
                verbose=False
            )
            result = finder.run()
            subs = [s.get('subdomain', '') for s in result.get('subdomains', []) if s.get('subdomain')]
            if self.verbose:
                print(f"  Wordlist: {len(subs)} found")
            return subs
        except:
            return []
    
    def run(self):
        """Execute all subdomain discovery methods."""
        if self.verbose:
            print(f"  🔍 Discovering subdomains for {self.target}...")
        
        # Try Subfinder first
        subfinder_subs = self.run_subfinder()
        
        # Try Amass second
        amass_subs = self.run_amass()
        
        # Fallback to wordlist
        wordlist_subs = self.run_bruteforce()
        
        # Merge all results
        all_subs = set(subfinder_subs + amass_subs + wordlist_subs)
        
        # Filter: only valid subdomains of target
        valid_subs = []
        for sub in all_subs:
            sub = sub.strip().lower()
            if sub and (sub == self.target or sub.endswith('.' + self.target)):
                # Skip wildcard and invalid
                if '*' not in sub and '..' not in sub:
                    valid_subs.append(sub)
        
        # Add target itself if not present
        if self.target not in valid_subs:
            valid_subs.append(self.target)
        
        # Sort and deduplicate
        valid_subs = sorted(set(valid_subs))
        
        if self.verbose:
            print(f"  ✅ Total unique subdomains: {len(valid_subs)}")
            for sub in valid_subs[:10]:
                print(f"    - {sub}")
            if len(valid_subs) > 10:
                print(f"    ... and {len(valid_subs)-10} more")
        
        return valid_subs
