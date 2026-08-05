#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
from core.logger import log_info, log_success
from modules.core.http_client import HTTPClient

class SocialEngineering:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.results = {}

    def generate_phishing_link(self, domain):
        """تولید لینک فیشینگ شبیه‌سازی شده"""
        log_info(f"Generating phishing links for {domain}")
        prefixes = ['secure', 'login', 'verify', 'account', 'webmail']
        suffixes = ['.com', '.net', '.org', '.info']
        link = f"https://{random.choice(prefixes)}-{domain.replace('.', '-')}{random.choice(suffixes)}"
        self.results['phishing_links'] = [link]
        log_success(f"Generated phishing link: {link}")
        return self.results['phishing_links']

    def search_leaked_emails(self):
        """جستجوی ایمیل‌های لو رفته"""
        log_info(f"Searching leaked emails for {self.target}")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            resp = self.client.get(url)
            if resp and resp.status_code == 200:
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
                self.results['leaked_emails'] = list(set(emails))
                log_success(f"Found {len(emails)} leaked emails")
        except:
            pass

    def run(self):
        log_info(f"Starting Social Engineering on: {self.target}")
        self.generate_phishing_link(self.target)
        self.search_leaked_emails()
        log_success("Social Engineering completed.")
        return {
            "target": self.target,
            "scan_type": "social_eng",
            "results": self.results
        }
