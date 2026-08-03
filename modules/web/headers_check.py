#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from core.logger import log_info, log_success, log_debug, log_error, log_warning

class SecurityHeadersChecker:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.headers_status = []

    def run(self):
        log_info(f"Starting Security Headers Check on: {self.target}")
        try:
            resp = requests.get(self.target, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code not in [200, 301, 302]:
                log_error(f"Cannot fetch page. Status: {resp.status_code}")
                return {"target": self.target, "scan_type": "headers_check", "headers": []}

            headers = resp.headers
            security_headers = {
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "XFO",
                "X-Content-Type-Options": "XCTO",
                "Strict-Transport-Security": "HSTS",
                "Referrer-Policy": "Referrer",
                "X-XSS-Protection": "XXP",
                "Permissions-Policy": "Permissions",
                "Feature-Policy": "Feature"
            }

            log_info("Checking security headers:")
            for header, short_name in security_headers.items():
                if header in headers:
                    self.headers_status.append({
                        "header": header,
                        "short": short_name,
                        "present": True,
                        "value": headers[header]
                    })
                    log_success(f"✅ {header}: {headers[header]}")
                else:
                    self.headers_status.append({
                        "header": header,
                        "short": short_name,
                        "present": False,
                        "value": None
                    })
                    log_warning(f"❌ {header} is missing")

            # Summary
            present_count = len([h for h in self.headers_status if h["present"]])
            log_success(f"Security Headers Check completed. {present_count}/{len(self.headers_status)} headers present.")

        except Exception as e:
            log_error(f"Error: {e}")

        return {
            "target": self.target,
            "scan_type": "headers_check",
            "total_checked": len(self.headers_status),
            "present_count": len([h for h in self.headers_status if h["present"]]),
            "headers": self.headers_status
        }
