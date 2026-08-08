#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient


class SecurityHeadersChecker:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)

    def run(self):
        log_info(f"Starting Security Headers Check on: {self.target}")
        resp = self.client.get(self.target)

        if not resp:
            log_error(f"Cannot fetch page.")
            return {
                "target": self.target,
                "scan_type": "headers_check",
                "total_checked": 0,
                "present_count": 0,
                "headers": [],
                "error": "Failed to fetch page",
            }

        headers = resp.headers

        # Full security headers list with descriptions
        security_headers = {
            "Content-Security-Policy": {
                "short": "CSP",
                "description": "Prevents XSS attacks and code injection",
            },
            "X-Frame-Options": {
                "short": "XFO",
                "description": "Prevents Clickjacking",
            },
            "X-Content-Type-Options": {
                "short": "XCTO",
                "description": "Prevents MIME sniffing",
            },
            "Strict-Transport-Security": {
                "short": "HSTS",
                "description": "Forces HTTPS usage",
            },
            "Referrer-Policy": {
                "short": "Referrer",
                "description": "Controls Referrer information",
            },
            "X-XSS-Protection": {
                "short": "XXP",
                "description": "Protects against XSS (legacy)",
            },
            "Permissions-Policy": {
                "short": "Permissions",
                "description": "Controls browser feature access",
            },
            "Feature-Policy": {
                "short": "Feature",
                "description": "Controls browser features (legacy)",
            },
            "Cross-Origin-Embedder-Policy": {
                "short": "COEP",
                "description": "Controls cross-origin embedding",
            },
            "Cross-Origin-Opener-Policy": {
                "short": "COOP",
                "description": "Controls cross-origin opener",
            },
            "Cross-Origin-Resource-Policy": {
                "short": "CORP",
                "description": "Controls cross-origin resource",
            },
        }

        results = []
        log_info("Checking security headers...")

        for header, info in security_headers.items():
            if header in headers:
                results.append(
                    {
                        "header": header,
                        "short": info["short"],
                        "present": True,
                        "value": headers[header],
                        "description": info["description"],
                    }
                )
                log_success(f"✅ {header}: {headers[header]}")
            else:
                results.append(
                    {
                        "header": header,
                        "short": info["short"],
                        "present": False,
                        "value": None,
                        "description": info["description"],
                    }
                )
                log_warning(f"❌ {header} is missing ({info['description']})")

        present_count = len([h for h in results if h["present"]])
        total_headers = len(results)

        log_success(
            f"Security Headers Check completed. {present_count}/{total_headers} headers present."
        )

        # Security rating based on number of present headers
        security_score = "Unknown"
        if present_count >= 8:
            security_score = "Excellent"
        elif present_count >= 6:
            security_score = "Good"
        elif present_count >= 4:
            security_score = "Moderate"
        elif present_count >= 2:
            security_score = "Weak"
        else:
            security_score = "Poor"

        log_info(f"Security Score: {security_score} ({present_count}/{total_headers})")

        return {
            "target": self.target,
            "scan_type": "headers_check",
            "total_checked": total_headers,
            "present_count": present_count,
            "security_score": security_score,
            "headers": results,
            "raw_headers": dict(headers),
        }
