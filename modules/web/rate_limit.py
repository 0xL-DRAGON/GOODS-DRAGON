#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class RateLimitChecker:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.results = []
        self.attempts = 20
        self.delay = 0.1

    def check_rate_limit(self):
        start_time = time.time()
        for i in range(self.attempts):
            try:
                resp = requests.get(self.target, timeout=5, allow_redirects=False)
                if resp.status_code == 429:
                    self.results.append({
                        "attempt": i+1,
                        "status": 429,
                        "message": "Rate limiting detected"
                    })
                    log_success(f"🔥 Rate limiting detected after {i+1} attempts")
                    return True
                elif resp.status_code == 200:
                    if i % 5 == 0 and self.verbose:
                        log_debug(f"Attempt {i+1}: {resp.status_code}")
                else:
                    if self.verbose:
                        log_debug(f"Attempt {i+1}: {resp.status_code}")
                time.sleep(self.delay)
            except Exception as e:
                if self.verbose:
                    log_debug(f"Error on attempt {i+1}: {e}")
        
        if not self.results:
            log_warning("No rate limiting detected")
            self.results.append({
                "attempts": self.attempts,
                "message": "No rate limiting detected"
            })
        return False

    def run(self):
        log_info(f"Starting Rate Limit check on: {self.target}")
        self.check_rate_limit()
        log_success(f"Rate limit check completed.")
        return {"target": self.target, "scan_type": "rate_limit", "results": self.results}
