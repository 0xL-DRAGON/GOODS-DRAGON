#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import random
import time

import cloudscraper
import requests
from fake_useragent import UserAgent
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from core.logger import log_error, log_info, log_success, log_warning


class BrowserEmulator:
    def __init__(
        self, target, verbose=False, headless=True, use_selenium=True, proxy_list=None
    ):
        self.target = target
        self.verbose = verbose
        self.headless = headless
        self.use_selenium = use_selenium
        self.proxy_list = proxy_list or []
        self.ua = UserAgent()
        self.session = None
        self.driver = None
        self._init_session()

    def _init_session(self):
        if self.use_selenium:
            self._init_selenium()
        else:
            self._init_requests()

    def _init_selenium(self):
        """Launch browser واقعی با Selenium و webdriver-manager"""
        options = Options()
        if self.headless:
            options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        options.add_argument(f"user-agent={self.ua.random}")

        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            options.add_argument(f"--proxy-server={proxy}")

        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            self.driver.execute_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            log_success("Selenium WebDriver initialized successfully.")
        except Exception as e:
            log_error(f"Failed to initialize Selenium: {e}")
            log_info("Falling back to requests mode.")
            self.use_selenium = False
            self._init_requests()

    def _init_requests(self):
        """راه‌اندازی session با cloudscraper و هدرهای واقعی"""
        self.session = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )
        self.session.headers.update(self.get_random_headers())

    def get_random_headers(self):
        """تولید هدرهای کاملاً واقعی شبیه مرورگر"""
        return {
            "User-Agent": self.ua.random,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
            "DNT": "1",
        }

    def get_random_proxy(self):
        if self.proxy_list:
            return random.choice(self.proxy_list)
        return None

    def random_delay(self, min_delay=1.0, max_delay=5.0):
        delay = random.uniform(min_delay, max_delay)
        if self.verbose:
            log_info(f"⏳ Sleeping for {delay:.2f} seconds...")
        time.sleep(delay)

    def fetch_with_selenium(self, url):
        """Fetch content با Selenium (اجرای کامل JS)"""
        try:
            if not self.driver:
                self._init_selenium()

            self.driver.get(url)
            time.sleep(3)  # منتظر بارگذاری کامل
            html = self.driver.page_source
            cookies = self.driver.get_cookies()

            log_success(f"Fetched {url} with Selenium (JS executed)")
            return {
                "content": html,
                "cookies": cookies,
                "status": 200,
                "url": self.driver.current_url,
            }
        except Exception as e:
            log_error(f"Selenium fetch failed: {e}")
            return None

    def fetch_with_requests(self, url, method="GET", data=None, retries=5):
        """Fetch content با requests + cloudscraper"""
        proxy = self.get_random_proxy()
        proxy_dict = {"http": proxy, "https": proxy} if proxy else None

        for attempt in range(retries):
            try:
                if self.verbose:
                    log_info(f"Request attempt {attempt+1}/{retries}...")

                self.session.headers.update(self.get_random_headers())

                if method.upper() == "GET":
                    resp = self.session.get(url, proxies=proxy_dict, timeout=15)
                else:
                    resp = self.session.post(
                        url, data=data, proxies=proxy_dict, timeout=15
                    )

                if resp.status_code == 200:
                    log_success(
                        f"Fetched {url} with requests (Status: {resp.status_code})"
                    )
                    return resp
                elif resp.status_code in [403, 429, 503]:
                    log_warning(f"Blocked ({resp.status_code}), retrying...")
                    self.random_delay(2.0, 8.0)
                    continue
                else:
                    log_info(f"Status: {resp.status_code}")
                    return resp

            except Exception as e:
                log_warning(f"Request failed: {e}, retrying...")
                self.random_delay(2.0, 8.0)

        return None

    def solve_challenge(self, url):
        """Attempt challenge solving‌های امنیتی"""
        log_info("Attempting to solve security challenge...")

        # مرحله ۱: استفاده از Selenium (اجرای JS)
        if self.use_selenium:
            result = self.fetch_with_selenium(url)
            if result:
                return result

        # مرحله ۲: استفاده از cloudscraper با تنظیمات پیشرفته
        log_info("Falling back to cloudscraper with advanced settings...")
        return self.fetch_with_requests(url)

    def run(self):
        log_info("=== Starting Browser Emulator ===")
        log_info(f"Target: {self.target}")
        log_info(f"User-Agent: {self.ua.random}")
        log_info(f"Selenium: {'Enabled' if self.use_selenium else 'Disabled'}")
        log_info(f"Headless: {'Enabled' if self.headless else 'Disabled'}")

        result = self.solve_challenge(self.target)

        if result:
            log_success("Browser Emulator completed successfully!")
            # تبدیل bytes به str برای JSON
            if hasattr(result, "content") and isinstance(result.content, bytes):
                content = result.content.decode("utf-8", errors="ignore")
            elif isinstance(result, dict) and "content" in result:
                content = result["content"]
                if isinstance(content, bytes):
                    content = content.decode("utf-8", errors="ignore")
            elif hasattr(result, "text"):
                content = result.text
            else:
                content = str(result)

            return {
                "target": self.target,
                "status": "success",
                "content": content[:2000] + "..." if len(content) > 2000 else content,
                "headers": dict(result.headers) if hasattr(result, "headers") else {},
                "cookies": dict(result.cookies) if hasattr(result, "cookies") else {},
            }
        else:
            log_error("Browser Emulator failed.")
            return {"target": self.target, "status": "failed"}
