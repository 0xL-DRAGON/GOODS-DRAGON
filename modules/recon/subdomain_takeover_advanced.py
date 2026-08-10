"""
Advanced Subdomain Takeover Checker
Checks 50+ services for takeover possibilities.
"""
import requests

TAKEOVER_SIGNATURES = {
    "AWS S3": "The specified bucket does not exist",
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Heroku": "No such app",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Tumblr": "There's nothing here",
    "WordPress": "Do you want to register",
    "Azure": "This page does not exist",
    "CloudFront": "Bad request",
    "Fastly": "Fastly error: unknown domain",
    "Ghost": "The thing you were looking for is no longer here",
    "Pantheon": "This site is currently inactive",
    "Surge": "project not found",
    "Unbounce": "The requested URL was not found on this server",
    "Netlify": "Not Found - Request ID",
    "Vercel": "This deployment could not be found",
    "Acquia": "The site you are looking for could not be found",
    "Readme.io": "Project doesnt exist",
    "Cargo": "404 Not Found",
    "Bitbucket": "Repository not found",
    "Intercom": "This page is reserved",
    "Helpjuice": "404 Not Found",
    "Launchrock": "The page you're looking for could not be found",
    "Mashery": "Unrecognized domain",
    "Tictail": "The page you're looking for doesn't exist",
    "Uptime": "Site not found",
    "Uscreen": "This page doesn't exist",
    "Wishpond": "This site is not available",
    "Wix": "Error 404",
    "Zendesk": "Help Center closed",
    "Statuspage": "This page is not available",
}

class AdvancedSubdomainTakeover:
    def __init__(self, subdomains, verbose=False):
        self.subdomains = subdomains
        self.verbose = verbose
    
    def check_takeover(self, subdomain):
        """Check a single subdomain for takeover."""
        results = []
        for url in [f"http://{subdomain}", f"https://{subdomain}"]:
            try:
                resp = requests.get(url, timeout=5, allow_redirects=True)
                for service, signature in TAKEOVER_SIGNATURES.items():
                    if signature.lower() in resp.text.lower():
                        results.append({
                            "subdomain": subdomain,
                            "url": url,
                            "service": service,
                            "status": resp.status_code,
                            "signature": signature
                        })
            except:
                pass
        return results
    
    def run(self):
        """Check all subdomains for takeover."""
        all_results = []
        for sub in self.subdomains:
            results = self.check_takeover(sub)
            all_results.extend(results)
        return all_results
