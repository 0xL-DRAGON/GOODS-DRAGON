#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests
from core.logger import log_info, log_success, log_warning
from modules.core.http_client import HTTPClient

class MobileSecurity:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.results = []

    def check_apk(self, apk_url):
        """بررسی امنیتی APK (شبیه‌سازی)"""
        log_info(f"Checking APK: {apk_url}")
        try:
            resp = self.client.get(apk_url, timeout=30)
            if resp and resp.status_code == 200:
                if 'dangerous' in resp.text.lower():
                    self.results.append({"type": "dangerous_permission", "url": apk_url})
                    log_warning("Potential dangerous permissions found")
        except:
            pass

    def check_ios(self, plist_url):
        """بررسی امنیتی iOS (شبیه‌سازی)"""
        log_info(f"Checking iOS plist: {plist_url}")

    def check_mobile_api(self):
        """بررسی APIهای موبایل"""
        log_info("Checking mobile API endpoints...")
        endpoints = [
            "/api/mobile",
            "/api/v1/mobile",
            "/api/ios",
            "/api/android",
            "/mobile/api",
            "/.well-known/apple-app-site-association",
            "/apple-app-site-association",
            "/.well-known/assetlinks.json"
        ]
        for endpoint in endpoints:
            url = f"{self.target}{endpoint}"
            resp = self.client.get(url)
            if resp and resp.status_code != 404:
                self.results.append({"type": "mobile_api", "url": url, "status": resp.status_code})
                log_success(f"Found mobile API: {url}")

    def check_android_manifest(self):
        """بررسی فایل AndroidManifest.xml"""
        log_info("Checking Android manifest...")
        url = f"{self.target}/AndroidManifest.xml"
        resp = self.client.get(url)
        if resp and resp.status_code == 200:
            self.results.append({"type": "android_manifest", "url": url, "status": resp.status_code})
            log_success("AndroidManifest.xml found")

    def run(self):
        log_info(f"Starting Mobile Security on: {self.target}")
        self.check_mobile_api()
        self.check_android_manifest()
        log_success(f"Mobile scan completed. Found {len(self.results)} items.")
        return {
            "target": self.target,
            "scan_type": "mobile_security",
            "total_found": len(self.results),
            "results": self.results
        }
