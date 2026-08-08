#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import time

import cloudscraper
import requests
from fake_useragent import UserAgent

from core.logger import log_error, log_info, log_success, log_warning


class WAFBypass:
    def __init__(
        self,
        target,
        verbose=False,
        proxy_list=None,
        rotate_ua=True,
        use_cloudscraper=True,
        random_delay=True,
    ):
        self.target = target
        self.verbose = verbose
        self.proxy_list = proxy_list or []
        self.rotate_ua = rotate_ua
        self.use_cloudscraper = use_cloudscraper
        self.random_delay = random_delay
        self.ua = UserAgent()
        self.session = self._create_session()
        self.cookies = {}
        self.headers = {}

    def _create_session(self):
        if self.use_cloudscraper:
            return cloudscraper.create_scraper(
                browser={"browser": "chrome", "platform": "windows", "mobile": False}
            )
        return requests.Session()

    def get_random_headers(self):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }
        if self.rotate_ua:
            headers["User-Agent"] = self.ua.random
        return headers

    def get_random_proxy(self):
        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            return {"http": proxy, "https": proxy}
        return None

    def random_delay_func(self, min_delay=1.0, max_delay=5.0):
        if self.random_delay:
            delay = random.uniform(min_delay, max_delay)
            if self.verbose:
                log_info(f"⏳ Sleeping for {delay:.2f} seconds...")
            time.sleep(delay)

    def add_random_params(self, url):
        """Add random parameters to URL to bypass WAF"""
        if "?" in url:
            url += f"&_={random.randint(100000, 999999)}"
        else:
            url += f"?_={random.randint(100000, 999999)}"
        return url

    def send_request(self, url, method="GET", data=None, retries=5):
        headers = self.get_random_headers()
        proxy = self.get_random_proxy()
        url = self.add_random_params(url)

        for attempt in range(retries):
            try:
                if method.upper() == "GET":
                    resp = self.session.get(
                        url, headers=headers, proxies=proxy, timeout=15
                    )
                else:
                    resp = self.session.post(
                        url, data=data, headers=headers, proxies=proxy, timeout=15
                    )

                if resp.status_code != 403 and resp.status_code != 429:
                    return resp

                if self.verbose:
                    log_warning(
                        f"Blocked ({resp.status_code}), retrying... (attempt {attempt+1}/{retries})"
                    )

                # Increase delay on each attempt
                self.random_delay_func(2.0, 8.0)

                # Change User-Agent on each attempt
                if self.rotate_ua:
                    headers["User-Agent"] = self.ua.random

            except Exception as e:
                if self.verbose:
                    log_warning(
                        f"Request failed: {e}, retrying... (attempt {attempt+1}/{retries})"
                    )
                self.random_delay_func(2.0, 8.0)

        return None

    def check_visibility(self):
        log_info("Checking WAF bypass configuration...")
        resp = self.send_request(self.target)
        if resp:
            log_success(f"WAF bypass test passed! Status: {resp.status_code}")
            log_success(f"Response length: {len(resp.text)} bytes")
            return True
        else:
            log_error("WAF bypass test failed. Target may be blocking.")
            return False

    def run(self):
        log_info("=== Starting WAF Bypass Mode ===")
        log_info(f"Target: {self.target}")
        log_info(f"User-Agent: {self.ua.random if self.rotate_ua else 'Fixed'}")
        if self.proxy_list:
            log_info(f"Proxy: {self.get_random_proxy()}")
        else:
            log_info("No proxy configured. Using direct connection.")
        log_info(f"Cloudscraper: {'Enabled' if self.use_cloudscraper else 'Disabled'}")
        log_info(f"Random Delay: {'Enabled' if self.random_delay else 'Disabled'}")

        self.check_visibility()
        log_success("WAF Bypass mode ready.")
        return {
            "target": self.target,
            "user_agent": self.ua.random if self.rotate_ua else None,
            "proxy": self.proxy_list[0] if self.proxy_list else None,
            "cloudscraper": self.use_cloudscraper,
            "status": "ready",
        }
