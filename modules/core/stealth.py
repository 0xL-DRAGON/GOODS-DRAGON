#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import requests
from core.logger import log_info, log_success, log_warning

class StealthMode:
    def __init__(self, target, verbose=False, proxy_list=None):
        self.target = target
        self.verbose = verbose
        self.proxy_list = proxy_list or []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
        ]

    def get_random_user_agent(self):
        return random.choice(self.user_agents)

    def get_random_proxy(self):
        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            return {"http": proxy, "https": proxy}
        return None

    def get_headers(self):
        return {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    def random_delay(self):
        delay = random.uniform(0.5, 2.0)
        log_info(f"⏳ Sleeping for {delay:.2f} seconds...")
        import time
        time.sleep(delay)

    def check_visibility(self):
        log_info("Checking stealth configuration...")
        headers = self.get_headers()
        proxy = self.get_random_proxy()
        try:
            resp = requests.get(self.target, headers=headers, proxies=proxy, timeout=10)
            log_success(f"Stealth test passed! Status: {resp.status_code}")
            return True
        except Exception as e:
            log_warning(f"Stealth test failed: {e}")
            return False

    def run(self):
        log_info("=== Starting Stealth Mode ===")
        log_info(f"Target: {self.target}")
        log_info(f"User-Agent: {self.get_random_user_agent()}")
        if self.proxy_list:
            log_info(f"Proxy: {self.get_random_proxy()}")
        else:
            log_info("No proxy configured. Using direct connection.")
        self.check_visibility()
        log_success("Stealth mode ready.")
        return {
            "target": self.target,
            "user_agent": self.get_random_user_agent(),
            "proxy": self.proxy_list[0] if self.proxy_list else None,
            "status": "ready"
        }
