#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class CORSChecker:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.results = []

    def check_cors(self):
        headers = {
            "Origin": "https://evil.com",
            "User-Agent": "Mozilla/5.0"
        }
        try:
            resp = requests.get(self.target, headers=headers, timeout=10, allow_redirects=False)
            if 'access-control-allow-origin' in resp.headers:
                acao = resp.headers['access-control-allow-origin']
                if acao == '*' or acao == 'https://evil.com':
                    result = {
                        "url": self.target,
                        "cors_header": acao,
                        "allow_credentials": resp.headers.get('access-control-allow-credentials', 'false'),
                        "vulnerable": True,
                        "severity": "High"
                    }
                    self.results.append(result)
                    log_success(f"🔥 CORS misconfiguration found: ACAO = {acao}")
                else:
                    log_info(f"CORS header present but safe: {acao}")
            else:
                log_info("No CORS header found")
        except Exception as e:
            log_error(f"Error checking CORS: {e}")
        return self.results

    def run(self):
        log_info(f"Starting CORS check on: {self.target}")
        self.check_cors()
        log_success(f"CORS check completed. Found {len(self.results)} misconfigurations.")
        return {"target": self.target, "scan_type": "cors", "total": len(self.results), "results": self.results}
