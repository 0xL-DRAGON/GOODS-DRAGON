"""
GOODS-DRAGON Web Spider/Crawler
Finds all links, forms, and parameters on a target website.
"""
import requests
import re
from urllib.parse import urljoin, urlparse

class Spider:
    def __init__(self, target, max_pages=50, verbose=False):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.max_pages = max_pages
        self.verbose = verbose
        self.visited = set()
        self.found_urls = set()
        self.found_forms = []
        self.params_found = set()
    
    def extract_links(self, html, base_url):
        """Extract all links from HTML."""
        links = set()
        # Find href links
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = urljoin(base_url, match.group(1))
            if url.startswith(('http://', 'https://')):
                links.add(url)
        return links
    
    def extract_params(self, url):
        """Extract GET parameters from URL."""
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    self.params_found.add(param.split('=')[0])
    
    def extract_forms(self, html, base_url):
        """Extract forms and their parameters."""
        forms = []
        for match in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE):
            action = urljoin(base_url, match.group(1))
            form_html = match.group(2)
            
            # Find input fields
            inputs = []
            for inp in re.finditer(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form_html, re.IGNORECASE):
                inputs.append(inp.group(1))
                self.params_found.add(inp.group(1))
            
            if inputs:
                forms.append({'action': action, 'inputs': inputs})
        
        return forms
    
    def crawl(self):
        """Crawl the target website."""
        to_visit = {self.target}
        
        while to_visit and len(self.visited) < self.max_pages:
            url = to_visit.pop()
            if url in self.visited:
                continue
            
            try:
                resp = requests.get(url, timeout=10, allow_redirects=True)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    self.visited.add(url)
                    
                    # Extract links
                    links = self.extract_links(resp.text, url)
                    for link in links:
                        parsed = urlparse(link)
                        # Only same domain
                        if parsed.netloc == urlparse(self.target).netloc:
                            self.found_urls.add(link)
                            self.extract_params(link)
                            if len(self.visited) + len(to_visit) < self.max_pages:
                                to_visit.add(link)
                    
                    # Extract forms
                    forms = self.extract_forms(resp.text, url)
                    self.found_forms.extend(forms)
                    
                    if self.verbose:
                        print(f"  Crawled: {url} ({len(links)} links, {len(forms)} forms)")
            except:
                pass
        
        return {
            'urls': list(self.found_urls),
            'forms': self.found_forms,
            'params': list(self.params_found),
            'pages_crawled': len(self.visited)
        }
    
    def run(self):
        """Execute spider."""
        print(f"🕷️ Spider crawling {self.target}...")
        result = self.crawl()
        print(f"  ✅ Crawled {result['pages_crawled']} pages")
        print(f"  ✅ Found {len(result['urls'])} URLs")
        print(f"  ✅ Found {len(result['forms'])} forms")
        print(f"  ✅ Found {len(result['params'])} unique parameters")
        return result
