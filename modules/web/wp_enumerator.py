"""
WordPress Plugin/Theme Enumerator for Bug Bounty
Finds outdated plugins with known CVEs.
"""
import requests

WP_PLUGINS = [
    "akismet", "contact-form-7", "woocommerce", "wordpress-seo",
    "elementor", "jetpack", "wpforms", "all-in-one-seo-pack",
    "wordfence", "really-simple-ssl", "duplicate-post", "wp-rocket",
    "updraftplus", "wp-super-cache", "w3-total-cache", "revslider",
    "wp-file-manager", "easy-wp-smtp", "litespeed-cache", "rank-math-seo",
    "classic-editor", "imagify", "sucuri-scanner", "limit-login-attempts",
    "gravityforms", "ninja-forms", "formidable", "wp-mail-smtp",
]

class WPEnumerator:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
    
    def check_plugin(self, plugin):
        """Check if a plugin is installed."""
        url = f"{self.target}/wp-content/plugins/{plugin}/readme.txt"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                # Extract version
                import re
                match = re.search(r'Stable tag:\s*(\d+\.\d+(\.\d+)?)', resp.text)
                version = match.group(1) if match else "Unknown"
                return {"plugin": plugin, "version": version, "url": url}
        except:
            pass
        return None
    
    def run(self):
        """Enumerate installed plugins."""
        results = []
        for plugin in WP_PLUGINS:
            result = self.check_plugin(plugin)
            if result:
                results.append(result)
        return results
