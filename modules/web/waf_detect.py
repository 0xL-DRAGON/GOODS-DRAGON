#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class WAFDetector:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.detected = []

        # WAF signatures (header + cookie + response patterns)
        self.waf_signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
                "cookies": ["__cfduid"],
                "response": ["cloudflare"],
            },
            "AWS WAF": {
                "headers": ["x-amzn-RequestId", "x-amzn-trace-id"],
                "cookies": [],
                "response": ["aws"],
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "x-akamai-request-id"],
                "cookies": ["ak_bmsc"],
                "response": ["akamai"],
            },
            "CloudFront": {
                "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
                "cookies": ["cloudfront"],
                "response": ["cloudfront"],
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "cookies": ["sucuri"],
                "response": ["sucuri"],
            },
            "Incapsula": {
                "headers": ["x-iinfo", "x-cdn"],
                "cookies": ["incap_ses"],
                "response": ["incapsula"],
            },
            "Barracuda": {
                "headers": ["x-cuda"],
                "cookies": ["barracuda"],
                "response": ["barracuda"],
            },
            "F5 BIG-IP": {
                "headers": ["x-bigip"],
                "cookies": ["BIGipServer"],
                "response": ["bigip"],
            },
            "ModSecurity": {
                "headers": ["x-modsecurity"],
                "cookies": [],
                "response": ["modsecurity"],
            },
            "Wordfence": {
                "headers": ["x-wordfence"],
                "cookies": ["wordfence"],
                "response": ["wordfence"],
            },
        }

    def run(self):
        log_info(f"Starting WAF Detection on: {self.target}")
        try:
            resp = requests.get(self.target, timeout=10, allow_redirects=False)
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies = {k.lower(): v.lower() for k, v in resp.cookies.items()}
            html = resp.text.lower()

            for waf, signatures in self.waf_signatures.items():
                detected = False

                # Check headers
                for header in signatures["headers"]:
                    if header.lower() in headers:
                        self.detected.append(
                            {"waf": waf, "type": "header", "signature": header}
                        )
                        detected = True
                        log_success(f"🔥 Detected WAF: {waf} (header: {header})")

                # Check cookies
                for cookie in signatures["cookies"]:
                    if cookie.lower() in cookies:
                        self.detected.append(
                            {"waf": waf, "type": "cookie", "signature": cookie}
                        )
                        detected = True
                        log_success(f"🔥 Detected WAF: {waf} (cookie: {cookie})")

                # Check response
                for pattern in signatures["response"]:
                    if pattern.lower() in html:
                        self.detected.append(
                            {"waf": waf, "type": "response", "signature": pattern}
                        )
                        detected = True
                        log_success(
                            f"🔥 Detected WAF: {waf} (response pattern: {pattern})"
                        )

            if not self.detected:
                log_info("No WAF detected.")

        except Exception as e:
            log_error(f"Error: {e}")

        return {
            "target": self.target,
            "scan_type": "waf_detect",
            "total_detected": len(self.detected),
            "wafs": self.detected,
        }
