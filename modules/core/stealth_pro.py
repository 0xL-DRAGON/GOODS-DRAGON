#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import time
import requests
import cloudscraper  # pip install cloudscraper
from core.logger import log_info, log_success, log_warning

class StealthPro:
    def __init__(self, target, verbose=False, proxy_list=None, rotate_ua=True, use_cloudscraper=True):
        self.target = target
        self.verbose = verbose
        self.proxy_list = proxy_list or []
        self.rotate_ua = rotate_ua
        self.use_cloudscraper = use_cloudscraper
        self.session = self._create_session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
        ]

    def _create_session(self):
        if self.use_cloudscraper:
            return cloudscraper.create_scraper()
        return requests.Session()

    def get_random_user_agent(self):
        return random.choice(self.user_agents)

    def get_random_proxy(self):
        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            return {"http": proxy, "https": proxy}
        return None

    def get_headers(self):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        if self.rotate_ua:
            headers["User-Agent"] = self.get_random_user_agent()
        return headers

    def random_delay(self, min_delay=1.0, max_delay=3.0):
        delay = random.uniform(min_delay, max_delay)
        if self.verbose:
            log_info(f"⏳ Sleeping for {delay:.2f} seconds...")
        time.sleep(delay)

    def send_request(self, url, method="GET", data=None, retries=3):
        headers = self.get_headers()
        proxy = self.get_random_proxy()
        for attempt in range(retries):
            try:
                if method.upper() == "GET":
                    resp = self.session.get(url, headers=headers, proxies=proxy, timeout=15)
                else:
                    resp = self.session.post(url, data=data, headers=headers, proxies=proxy, timeout=15)
                if resp.status_code != 403 and resp.status_code != 429:
                    return resp
                if self.verbose:
                    log_warning(f"Blocked ({resp.status_code}), retrying...")
                self.random_delay(2, 5)
            except Exception as e:
                if self.verbose:
                    log_warning(f"Request failed: {e}, retrying...")
                self.random_delay(2, 5)
        return None

    def check_visibility(self):
        log_info("Checking stealth configuration...")
        resp = self.send_request(self.target)
        if resp:
            log_success(f"Stealth test passed! Status: {resp.status_code}")
            return True
        else:
            log_warning("Stealth test failed. Target may be blocking.")
            return False

    def run(self):
        log_info("=== Starting Stealth Pro Mode ===")
        log_info(f"Target: {self.target}")
        log_info(f"User-Agent: {self.get_random_user_agent()}")
        if self.proxy_list:
            log_info(f"Proxy: {self.get_random_proxy()}")
        else:
            log_info("No proxy configured. Using direct connection.")
        log_info(f"Cloudscraper: {'Enabled' if self.use_cloudscraper else 'Disabled'}")
        self.check_visibility()
        log_success("Stealth Pro mode ready.")
        return {
            "target": self.target,
            "user_agent": self.get_random_user_agent(),
            "proxy": self.proxy_list[0] if self.proxy_list else None,
            "cloudscraper": self.use_cloudscraper,
            "status": "ready"
        }
