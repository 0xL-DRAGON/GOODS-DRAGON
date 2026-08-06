#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

import requests

from core.logger import log_debug, log_error, log_info, log_success


class WaybackScanner:
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = []

    def fetch_urls(self):
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    for item in data[1:]:
                        self.results.append(item[0])
                log_success(
                    f"Found {len(self.results)} historical URLs from Wayback Machine"
                )
            else:
                log_error(f"Wayback API returned status: {resp.status_code}")
        except Exception as e:
            log_error(f"Error fetching Wayback data: {e}")
        return self.results

    def run(self):
        log_info(f"Fetching historical URLs for: {self.domain}")
        urls = self.fetch_urls()
        return {
            "target": self.domain,
            "scan_type": "wayback",
            "total_urls": len(urls),
            "urls": urls[:500],  # محدود کردن به ۵۰۰ عدد برای جلوگیری از حجم بالا
        }
