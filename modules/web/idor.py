#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class IDORScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.vulnerable = []
        self.params_to_test = ['id', 'user', 'page', 'cat', 'product', 'order', 'ref', 'doc', 'file', 'item']

    def extract_params(self):
        parsed = urlparse(self.target)
        if not parsed.query:
            return {}
        return parse_qs(parsed.query)

    def build_url(self, params):
        parsed = urlparse(self.target)
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def test_idor(self, param, original_value):
        test_values = [str(int(original_value) + 1), str(int(original_value) - 1), '1', '0', 'admin', 'test']
        for test_val in test_values:
            params = self.extract_params()
            if param in params:
                params[param] = [test_val]
            else:
                params[param] = test_val
            test_url = self.build_url(params)
            try:
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    if len(resp.text) > 100 and 'login' not in resp.text.lower() and 'error' not in resp.text.lower():
                        result = {
                            "param": param,
                            "original": original_value,
                            "tested": test_val,
                            "url": test_url,
                            "status": resp.status_code,
                            "potential_idor": True
                        }
                        self.vulnerable.append(result)
                        log_success(f"🔥 Potential IDOR found on {param} with value {test_val}")
                        return result
                elif self.verbose:
                    log_debug(f"Tested {param}={test_val} -> {resp.status_code}")
            except Exception as e:
                if self.verbose:
                    log_debug(f"Error testing {param}: {e}")
        return None

    def run(self):
        log_info(f"Starting IDOR scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning("No GET parameters found. IDOR scan works best with parameters like ?id=1")
            return {"target": self.target, "scan_type": "idor", "vulnerable": []}
        
        for param, values in params.items():
            if param.lower() in self.params_to_test:
                original_value = values[0] if values else "1"
                if original_value.isdigit():
                    log_info(f"Testing parameter: {param} (original: {original_value})")
                    self.test_idor(param, original_value)
                elif self.verbose:
                    log_debug(f"Skipping {param} (non-numeric value: {original_value})")
        
        log_success(f"IDOR scan completed. Found {len(self.vulnerable)} potential vulnerabilities.")
        return {"target": self.target, "scan_type": "idor", "total": len(self.vulnerable), "vulnerable": self.vulnerable}
