#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class BusinessLogicChecker:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.results = []

    def check_parameter_manipulation(self):
        """Check for business logic flaws via parameter manipulation"""
        log_info("Checking parameter manipulation...")
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            log_warning("No GET parameters found")
            return

        for param, values in params.items():
            original_value = values[0] if values else "1"

            # Test with negative values
            if original_value.isdigit():
                test_values = [str(-int(original_value)), "0", "999999", "-999999"]
                for test_val in test_values:
                    params[param] = [test_val]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    try:
                        resp = requests.get(test_url, timeout=5, allow_redirects=False)
                        if resp.status_code == 200 and "error" not in resp.text.lower():
                            result = {
                                "param": param,
                                "original": original_value,
                                "tested": test_val,
                                "url": test_url,
                                "status": resp.status_code,
                                "type": "parameter_manipulation",
                            }
                            self.results.append(result)
                            log_success(
                                f"🔥 Parameter manipulation possible: {param}={test_val}"
                            )
                    except Exception as e:
                        if self.verbose:
                            log_debug(f"Error testing {param}: {e}")

    def check_workflow_bypass(self):
        """Check for workflow bypass vulnerabilities"""
        log_info("Checking workflow bypass...")
        steps = ["/step1", "/step2", "/step3"]
        for step in steps:
            try:
                url = f"{self.target}{step}"
                resp = requests.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    result = {
                        "url": url,
                        "status": resp.status_code,
                        "type": "workflow_bypass",
                    }
                    self.results.append(result)
                    log_success(f"🔥 Workflow bypass possible: {url} (direct access)")
            except Exception as e:
                if self.verbose:
                    log_debug(f"Error checking {step}: {e}")

    def check_batch_requests(self):
        """Check for batch request vulnerabilities"""
        log_info("Checking batch requests...")
        # Test for batch processing vulnerabilities
        test_urls = [
            f"{self.target}?ids=1,2,3,4,5",
            f"{self.target}?ids[]=1&ids[]=2&ids[]=3",
            f"{self.target}?user=admin&user=root&user=test",
        ]
        for test_url in test_urls:
            try:
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 100:
                    result = {
                        "url": test_url,
                        "status": resp.status_code,
                        "type": "batch_processing",
                    }
                    self.results.append(result)
                    log_success(f"🔥 Batch processing possible: {test_url}")
            except Exception as e:
                if self.verbose:
                    log_debug(f"Error testing {test_url}: {e}")

    def run(self):
        log_info(f"Starting Business Logic Check on: {self.target}")

        self.check_parameter_manipulation()
        self.check_workflow_bypass()
        self.check_batch_requests()

        log_success(
            f"Business Logic Check completed. Found {len(self.results)} issues."
        )
        return {
            "target": self.target,
            "scan_type": "business_logic",
            "total_issues": len(self.results),
            "results": self.results,
        }
