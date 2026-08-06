#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

import dns.resolver
import requests

from core.logger import log_error, log_info, log_success, log_warning
from modules.core.http_client import HTTPClient


class OSINT:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.client = HTTPClient(timeout=20, retries=3, verbose=verbose)
        self.results = {}

    def email_search(self):
        """جستجوی ایمیل‌های مرتبط با دامنه"""
        log_info(f"Searching emails for: {self.target}")
        emails = []
        try:
            # جستجو در GitHub
            url = f"https://api.github.com/search/code?q={self.target}+in:file+extension:py+extension:js+extension:json"
            resp = self.client.get(url)
            if resp and resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", []):
                    if "email" in str(item).lower():
                        emails.append(item.get("html_url", ""))
                log_success(f"Found {len(emails)} email references from GitHub")

            # جستجوی ساده با Google Dorks (شبیه‌سازی)
            dorks = [
                f'site:{self.target} "@gmail.com"',
                f'site:{self.target} "@yahoo.com"',
                f'site:{self.target} "@outlook.com"',
            ]
            for dork in dorks:
                log_info(f"Dork: {dork}")
        except Exception as e:
            log_error(f"Email search error: {e}")

        self.results["emails"] = emails
        return emails

    def domain_info(self):
        """اطلاعات WHOIS و DNS دامنه"""
        log_info(f"Getting domain info for: {self.target}")
        info = {}
        try:
            # WHOIS (ساده)
            resp = self.client.get(
                f"https://api.hackertarget.com/whois/?q={self.target}"
            )
            if resp and resp.status_code == 200:
                info["whois"] = resp.text[:500] + "..."
                log_success("WHOIS info retrieved")

            # DNS Records
            records = {}
            for record_type in ["A", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(self.target, record_type)
                    records[record_type] = [str(r) for r in answers]
                except:
                    records[record_type] = []
            info["dns"] = records
        except Exception as e:
            log_error(f"Domain info error: {e}")

        self.results["domain_info"] = info
        return info

    def phone_search(self):
        """جستجوی شماره تلفن مرتبط (شبیه‌سازی)"""
        log_info(f"Searching phone numbers for: {self.target}")
        phones = []
        try:
            # جستجو در متن‌های عمومی (شبیه‌سازی)
            resp = self.client.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            )
            if resp and resp.status_code == 200:
                text = resp.text
                phone_pattern = r"\b(\+?98|0)?9[0-9]{9}\b"
                phones = re.findall(phone_pattern, text)
                log_success(f"Found {len(phones)} phone numbers")
        except Exception as e:
            log_error(f"Phone search error: {e}")

        self.results["phones"] = phones
        return phones

    def social_media_search(self):
        """جستجوی پروفایل‌های شبکه‌های اجتماعی"""
        log_info(f"Searching social media for: {self.target}")
        profiles = {}
        platforms = {
            "twitter": f"https://twitter.com/{self.target}",
            "instagram": f"https://instagram.com/{self.target}",
            "github": f"https://github.com/{self.target}",
            "linkedin": f"https://linkedin.com/in/{self.target}",
            "telegram": f"https://t.me/{self.target}",
        }
        for platform, url in platforms.items():
            try:
                resp = self.client.head(url)
                if resp and resp.status_code == 200:
                    profiles[platform] = "exists"
                    log_success(f"Found {platform} profile")
                else:
                    profiles[platform] = "not_found"
            except:
                profiles[platform] = "error"

        self.results["social_media"] = profiles
        return profiles

    def run(self):
        log_info(f"Starting OSINT on: {self.target}")
        self.email_search()
        self.domain_info()
        self.phone_search()
        self.social_media_search()
        log_success(f"OSINT completed. Found {len(self.results)} data types.")
        return {"target": self.target, "scan_type": "osint", "results": self.results}
