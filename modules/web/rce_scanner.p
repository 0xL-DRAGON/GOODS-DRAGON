#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Dict, Optional
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class RCEScanner:
    """
    Remote Code Execution Scanner with Payload Manager Integration
    Detects command injection and RCE vulnerabilities
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.payloads_tested = 0

        # Load payloads from Payload Manager
        self.cmd_payloads = self._load_payloads("rce", ["cmd", "basic"])
        self.php_payloads = self._load_payloads("rce", ["php"])
        self.system_payloads = self._load_payloads("rce", ["system"])

        # Fallback to default payloads if database is empty
        if not self.cmd_payloads:
            self.cmd_payloads = self._default_payloads()

        # Indicators of RCE in response
        self.success_indicators = [
            "uid=", "root", "admin", "user", "System Information",
            "Microsoft Windows", "Linux", "Directory of", "Volume Serial Number",
            "vulnerable", "test", "whoami", "id", "ls", "dir", "echo"
        ]

    def _load_payloads(self, category: str, tags: List[str]) -> List[str]:
        """Load payloads from Payload Manager by category and tags"""
        payloads = []
        for tag in tags:
            results = self.payload_manager.get_payloads(category, tags=[tag], limit=30)
            for p in results:
                if 'value' in p:
                    payloads.append(p['value'])
        return list(set(payloads))

    def _default_payloads(self) -> List[str]:
        """Default RCE payloads if database is empty"""
        return [
            "?cmd=id",
            "?cmd=whoami",
            "?cmd=echo test",
            "?cmd=ls",
            "?cmd=system('id')",
            "?cmd=system('whoami')",
            "?cmd=system('echo test')",
            "?cmd=shell_exec('id')",
            "?cmd=exec('id')",
            "?cmd=passthru('id')",
            "?cmd=system('dir')",
            "?cmd=echo vulnerable",
            "?cmd=dir",
            "?cmd=ls"
        ]

    def test_rce(self, payload: str) -> bool:
        """Test a single RCE payload"""
        test_url = f"{self.target}{payload}"
        resp = self.client.get(test_url)
        if not resp:
            return False
        
        self.payloads_tested += 1
        
        for indicator in self.success_indicators:
            if indicator.lower() in resp.text.lower():
                result = {
                    "payload": payload,
                    "url": test_url,
                    "indicator": indicator,
                    "status": resp.status_code
                }
                self.results.append(result)
                log_success(f"Potential RCE found: {test_url} (indicator: {indicator})")
                return True
        return False

    def run(self) -> Dict:
        log_info(f"Starting RCE Scanner on: {self.target}")
        
        # Combine all payloads
        all_payloads = list(set(self.cmd_payloads + self.php_payloads + self.system_payloads))
        log_info(f"Testing {len(all_payloads)} RCE payloads...")
        
        for payload in all_payloads:
            self.test_rce(payload)
        
        log_success(f"RCE scan completed. Found {len(self.results)} issues.")
        return {
            "target": self.target,
            "scan_type": "rce_scanner",
            "total_found": len(self.results),
            "results": self.results,
            "payloads_tested": self.payloads_tested
        }
