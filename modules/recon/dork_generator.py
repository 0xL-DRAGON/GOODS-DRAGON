"""
Google Dork Generator for Bug Bounty
Generates search queries to find sensitive info.
"""

class DorkGenerator:
    def __init__(self, target):
        self.target = target
    
    def generate(self):
        """Generate Google dorks for the target."""
        return [
            f'site:{self.target} filetype:pdf',
            f'site:{self.target} filetype:sql',
            f'site:{self.target} filetype:env',
            f'site:{self.target} filetype:log',
            f'site:{self.target} inurl:admin',
            f'site:{self.target} inurl:login',
            f'site:{self.target} inurl:wp-admin',
            f'site:{self.target} inurl:phpinfo',
            f'site:{self.target} intext:"index of /"',
            f'site:{self.target} intext:"apache" intitle:"index of"',
            f'site:{self.target} intext:"password"',
            f'site:{self.target} intext:"api_key"',
            f'site:{self.target} intext:"secret"',
            f'site:{self.target} intext:"token"',
            f'site:{self.target} intext:"database"',
            f'site:{self.target} intitle:"test"',
            f'site:{self.target} intitle:"staging"',
            f'site:{self.target} intitle:"dev"',
            f'site:{self.target} ext:sql intext:"password"',
            f'site:{self.target} ext:log intext:"error"',
        ]
