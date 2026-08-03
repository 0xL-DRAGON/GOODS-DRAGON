#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class OpenRedirectScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.vulnerable = []
        self.payloads = [
            "http://evil.com",
            "//evil.com",
            "https://evil.com",
            "http://evil.com/redirect",
            "//evil.com/redirect",
            "https://evil.com/redirect",
            "//evil.com%2f",
            "http://evil.com%2f",
            "https://evil.com%2f",
            "//evil.com/",
            "http://evil.com/"
        ]

    def extract_params(self):
        parsed = urlparse(self.target)
        if not parsed.query:
            return {}
        return parse_qs(parsed.query)

    def build_url(self, params):
        parsed = urlparse(self.target)
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def test_redirect(self, param, payload):
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('location', '')
                if 'evil.com' in location:
                    result = {
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "status": resp.status_code,
                        "location": location,
                        "vulnerable": True
                    }
                    self.vulnerable.append(result)
                    log_success(f"🔥 Open Redirect found on {param} with payload: {payload}")
                    return True
                elif self.verbose:
                    log_debug(f"Param {param} with {payload} -> Redirect to {location}")
            elif self.verbose:
                log_debug(f"Param {param} with {payload} -> {resp.status_code}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error: {e}")
        return False

    def run(self):
        log_info(f"Starting Open Redirect scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning("No GET parameters found. Open Redirect scan works best with parameters like ?url=http://example.com")
            return {"target": self.target, "scan_type": "open_redirect", "vulnerable": []}
        
        url_params = [p for p in params.keys() if 'url' in p.lower() or 'redirect' in p.lower() or 'next' in p.lower() or 'return' in p.lower()]
        if not url_params:
            url_params = list(params.keys())[:3]
        
        for param in url_params:
            log_info(f"Testing parameter: {param}")
            for payload in self.payloads:
                if self.test_redirect(param, payload):
                    break
        
        log_success(f"Open Redirect scan completed. Found {len(self.vulnerable)} vulnerabilities.")
        return {"target": self.target, "scan_type": "open_redirect", "total": len(self.vulnerable), "vulnerable": self.vulnerable}
