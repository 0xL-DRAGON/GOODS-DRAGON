#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
import threading
from core.logger import log_info, log_success, log_warning, log_error

class AutoThrottle:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.results = {
            "rate_limit": None,
            "waf_detected": False,
            "recommended_threads": 5,
            "recommended_delay": 0.5,
            "test_results": []
        }
        self.lock = threading.Lock()

    def test_request(self, delay=0):
        """Send a single request with optional delay"""
        if delay > 0:
            time.sleep(delay)
        try:
            start = time.time()
            resp = requests.get(self.target, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            elapsed = time.time() - start
            return {
                "status": resp.status_code,
                "time": elapsed,
                "blocked": resp.status_code in [403, 429, 503, 447]
            }
        except requests.exceptions.Timeout:
            return {"status": "timeout", "time": 5, "blocked": True}
        except Exception as e:
            return {"status": "error", "error": str(e), "blocked": True}

    def detect_rate_limit(self):
        """Detect rate limiting by sending incremental requests"""
        log_info("Detecting rate limit...")
        results = []
        
        # Test 1: Single request (baseline)
        res1 = self.test_request(delay=0)
        results.append({"test": "single", "result": res1})
        
        if res1.get("blocked"):
            log_warning("First request was blocked! Target may have strict WAF.")
            self.results["waf_detected"] = True
            return
        
        # Test 2: 5 requests with 0.2s delay
        log_info("Testing with 5 requests (0.2s delay)...")
        blocked_count = 0
        for i in range(5):
            res = self.test_request(delay=0.2)
            results.append({"test": "5x_0.2s", "result": res})
            if res.get("blocked"):
                blocked_count += 1
            if i == 0 and res.get("blocked"):
                break
        
        # Test 3: 10 requests with 0.1s delay (if not blocked)
        if blocked_count < 2:
            log_info("Testing with 10 requests (0.1s delay)...")
            for i in range(10):
                res = self.test_request(delay=0.1)
                results.append({"test": "10x_0.1s", "result": res})
                if res.get("blocked"):
                    blocked_count += 1
        
        # Analyze results
        total_requests = len([r for r in results if r["result"].get("status") not in ["timeout", "error"]])
        blocked_requests = len([r for r in results if r["result"].get("blocked")])
        
        if blocked_requests > total_requests * 0.3:
            self.results["rate_limit"] = "strict"
            self.results["recommended_threads"] = 2
            self.results["recommended_delay"] = 1.0
            log_warning("Rate limiting detected! Target is strict.")
        elif blocked_requests > 0:
            self.results["rate_limit"] = "moderate"
            self.results["recommended_threads"] = 5
            self.results["recommended_delay"] = 0.5
            log_warning("Moderate rate limiting detected.")
        else:
            self.results["rate_limit"] = "none"
            self.results["recommended_threads"] = 10
            self.results["recommended_delay"] = 0.2
            log_success("No rate limiting detected.")

        self.results["test_results"] = results

    def run(self):
        log_info(f"Starting Auto-Throttle scan on: {self.target}")
        self.detect_rate_limit()
        
        log_success("Auto-Throttle scan completed.")
        log_info(f"  Rate Limit Status: {self.results['rate_limit']}")
        log_info(f"  Recommended Threads: {self.results['recommended_threads']}")
        log_info(f"  Recommended Delay: {self.results['recommended_delay']}s")
        
        return {
            "target": self.target,
            "scan_type": "auto_throttle",
            "results": self.results
        }
