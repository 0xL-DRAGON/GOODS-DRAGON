#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class SSTIScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.vulnerable = []
        self.payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("<%= 7*7 %>", "49"),
            ("{{config}}", "config"),
            ("{{self.__class__.__mro__}}", "__mro__"),
            ("{{''.__class__.__mro__[2].__subclasses__()}}", "subclasses"),
            ("${7*7}", "49"),
            ("{{7*7}}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("{{config}}", "config")
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

    def test_ssti(self, param, payload, expected):
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            if expected in resp.text:
                result = {
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "status": resp.status_code,
                    "vulnerable": True
                }
                self.vulnerable.append(result)
                log_success(f"🔥 SSTI found on {param} with payload: {payload}")
                return True
            elif self.verbose:
                log_debug(f"Param {param} with {payload} -> Not reflected")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error: {e}")
        return False

    def run(self):
        log_info(f"Starting SSTI scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning("No GET parameters found. SSTI scan works best with parameters like ?name=test")
            return {"target": self.target, "scan_type": "ssti", "vulnerable": []}
        
        for param in params.keys():
            log_info(f"Testing parameter: {param}")
            for payload, expected in self.payloads:
                if self.test_ssti(param, payload, expected):
                    break
        
        log_success(f"SSTI scan completed. Found {len(self.vulnerable)} vulnerabilities.")
        return {"target": self.target, "scan_type": "ssti", "total": len(self.vulnerable), "vulnerable": self.vulnerable}
