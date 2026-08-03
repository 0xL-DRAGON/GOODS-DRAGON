#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class RaceConditionDetector:
    def __init__(self, target, threads=50, verbose=False):
        self.target = target.rstrip('/')
        self.threads = threads
        self.verbose = verbose
        self.results = []
        self.lock = threading.Lock()

    def send_request(self, url, method="GET", data=None):
        """Send a single request"""
        try:
            if method == "GET":
                resp = requests.get(url, timeout=5, allow_redirects=False)
            else:
                resp = requests.post(url, data=data, timeout=5, allow_redirects=False)
            return resp.status_code, resp.text
        except Exception as e:
            if self.verbose:
                log_debug(f"Request error: {e}")
            return None, None

    def test_race_condition(self, url, method="GET", data=None, count=20):
        """Test for race condition by sending simultaneous requests"""
        results = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.send_request, url, method, data) for _ in range(count)]
            for future in as_completed(futures):
                try:
                    status, content = future.result()
                    if status is not None:
                        results.append((status, content))
                except Exception as e:
                    if self.verbose:
                        log_debug(f"Error: {e}")
        
        elapsed = time.time() - start_time
        
        # Check for anomalies
        statuses = [r[0] for r in results if r[0] is not None]
        if len(set(statuses)) > 1:
            result = {
                "url": url,
                "method": method,
                "statuses": statuses,
                "count": len(statuses),
                "time": elapsed,
                "type": "race_condition"
            }
            with self.lock:
                self.results.append(result)
                log_success(f"🔥 Race condition possible: {url} (statuses: {set(statuses)})")
        elif self.verbose:
            log_debug(f"No race condition detected: {url}")

    def run(self):
        log_info(f"Starting Race Condition Detection on: {self.target}")
        
        # Test with GET requests
        self.test_race_condition(self.target, "GET", count=20)
        
        # Test with POST if target has forms
        try:
            resp = requests.get(self.target, timeout=5)
            if 'form' in resp.text.lower():
                self.test_race_condition(self.target, "POST", data={"test": "1"}, count=20)
        except:
            pass
        
        log_success(f"Race Condition Detection completed. Found {len(self.results)} issues.")
        return {
            "target": self.target,
            "scan_type": "race_condition",
            "total_issues": len(self.results),
            "results": self.results
        }
