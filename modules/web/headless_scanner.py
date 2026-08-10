"""
GOODS-DRAGON Headless Browser Scanner
Uses Playwright to execute JavaScript and analyze final DOM.
Detects: DOM XSS, postMessage vulnerabilities, CSP bypasses, Prototype Pollution
"""
import os
import re

class HeadlessScanner:
    def __init__(self, target, verbose=False):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.verbose = verbose
        self.findings = []
    
    def scan(self):
        """Run headless browser scan."""
        try:
            from playwright.sync_api import sync_playwright
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                # Navigate to target
                page.goto(self.target, timeout=15000)
                page.wait_for_load_state('networkidle')
                
                # Get final DOM
                html = page.content()
                
                # Check for DOM-based XSS sinks
                self._check_dom_xss(page, html)
                
                # Check for postMessage listeners
                self._check_postmessage(page)
                
                # Check for Prototype Pollution
                self._check_prototype_pollution(page)
                
                # Check CSP effectiveness
                self._check_csp_bypass(page)
                
                browser.close()
                
        except ImportError:
            if self.verbose:
                print("  [!] Playwright not installed. Install with: pip install playwright && playwright install chromium")
        except Exception as e:
            if self.verbose:
                print(f"  [!] Headless scanner error: {e}")
        
        return self.findings
    
    def _check_dom_xss(self, page, html):
        """Check for DOM XSS sinks."""
        sinks = ['eval(', 'innerHTML', 'document.write', 'setTimeout(', 'setInterval(',
                 'location.href', 'location.replace', '$.html', 'jQuery.html']
        
        for sink in sinks:
            if sink in html:
                self.findings.append({
                    'type': 'DOM XSS Sink',
                    'severity': 'MEDIUM',
                    'description': f'Potential DOM XSS sink found: {sink}. Review if user input reaches this sink.',
                    'url': self.target,
                    'sink': sink
                })
    
    def _check_postmessage(self, page):
        """Check for insecure postMessage handlers."""
        try:
            result = page.evaluate("""() => {
                const issues = [];
                // Check if there's a postMessage listener without origin check
                const scripts = document.querySelectorAll('script');
                scripts.forEach(s => {
                    if (s.textContent && s.textContent.includes('postMessage') && 
                        !s.textContent.includes('event.origin')) {
                        issues.push('postMessage listener without origin validation');
                    }
                });
                return issues;
            }""")
            
            for issue in result:
                self.findings.append({
                    'type': 'Insecure postMessage',
                    'severity': 'HIGH',
                    'description': issue,
                    'url': self.target
                })
        except:
            pass
    
    def _check_prototype_pollution(self, page):
        """Check for Prototype Pollution vulnerabilities."""
        try:
            result = page.evaluate("""() => {
                const issues = [];
                // Check if Object prototype is polluted
                const obj = {};
                if (obj.polluted || obj.constructor.prototype.polluted) {
                    issues.push('Prototype pollution detected');
                }
                return issues;
            }""")
            
            for issue in result:
                self.findings.append({
                    'type': 'Prototype Pollution',
                    'severity': 'HIGH',
                    'description': issue,
                    'url': self.target
                })
        except:
            pass
    
    def _check_csp_bypass(self, page):
        """Check if CSP can be bypassed."""
        try:
            csp = page.evaluate("""() => {
                const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                return csp ? csp.content : null;
            }""")
            
            if csp and "'unsafe-inline'" in csp:
                self.findings.append({
                    'type': 'Weak CSP',
                    'severity': 'LOW',
                    'description': f'CSP allows unsafe-inline: {csp}',
                    'url': self.target
                })
        except:
            pass
    
    def run(self):
        """Execute headless scanner."""
        if self.verbose:
            print(f"  🖥️ Headless Browser scanning {self.target}...")
        
        findings = self.scan()
        
        if findings:
            for f in findings:
                print(f"  🔍 Found: {f['type']} ({f['severity']})")
        elif self.verbose:
            print("  ✅ No headless-specific issues found")
        
        return findings
