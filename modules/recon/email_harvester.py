#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

import requests

from core.logger import log_info, log_success
from modules.core.http_client import HTTPClient


class EmailHarvester:
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.emails = []

    def search_google(self):
        """Search emails در Google (Simulation)"""
        log_info(f"Searching Google for emails in {self.domain}")
        dorks = [
            f"site:{self.domain} @gmail.com",
            f"site:{self.domain} @yahoo.com",
            f"site:{self.domain} @outlook.com",
            f"site:{self.domain} @protonmail.com",
        ]
        for dork in dorks:
            log_info(f"Dork: {dork}")
        # در واقعیت نیاز به Google API یا scraping داره

    def search_github(self):
        """Search emails در GitHub"""
        log_info(f"Searching GitHub for emails in {self.domain}")
        try:
            url = f"https://api.github.com/search/code?q={self.domain}+in:file+extension:py+extension:js+extension:json"
            resp = self.client.get(url)
            if resp and resp.status_code == 200:
                data = resp.json()
                email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                for item in data.get("items", []):
                    if "email" in str(item).lower():
                        self.emails.append(item.get("html_url", ""))
                log_success(f"Found {len(self.emails)} emails from GitHub")
        except Exception as e:
            log_info(f"GitHub search error: {e}")

    def search_web(self):
        """جستجوی عمومی در وب"""
        log_info(f"Searching web for emails in {self.domain}")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = self.client.get(url)
            if resp and resp.status_code == 200:
                email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                found = re.findall(email_pattern, resp.text)
                self.emails.extend(found)
                log_success(f"Found {len(found)} emails from web search")
        except Exception as e:
            log_info(f"Web search error: {e}")

    def run(self):
        log_info(f"Starting Email Harvesting on: {self.domain}")
        self.search_google()
        self.search_github()
        self.search_web()
        log_success(f"Email Harvesting completed. Found {len(self.emails)} emails.")
        return {
            "target": self.domain,
            "scan_type": "email_harvester",
            "total_found": len(self.emails),
            "emails": list(set(self.emails)),
        }
