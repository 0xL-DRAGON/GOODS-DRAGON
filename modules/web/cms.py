#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class CMSDetector:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.cms_signatures = {
            "WordPress": [
                r'wp-content',
                r'wp-includes',
                r'wp-json',
                r'WordPress',
                r'wp-admin'
            ],
            "Joomla": [
                r'joomla',
                r'Joomla!',
                r'components/com_',
                r'administrator',
                r'media/system'
            ],
            "Drupal": [
                r'drupal',
                r'Drupal',
                r'sites/all',
                r'misc/drupal',
                r'drupal.org'
            ],
            "Magento": [
                r'magento',
                r'Magento',
                r'skin/frontend',
                r'app/code/core'
            ],
            "Shopify": [
                r'shopify',
                r'Shopify',
                r'cdn.shopify.com',
                r'myshopify.com'
            ],
            "Wix": [
                r'wix.com',
                r'Wix',
                r'static.wixstatic.com'
            ],
            "Laravel": [
                r'laravel',
                r'Laravel',
                r'vendor/laravel'
            ]
        }
        self.detected = []

    def run(self):
        log_info(f"Starting CMS Detection on: {self.target}")
        try:
            resp = requests.get(self.target, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                log_error(f"Cannot fetch page. Status: {resp.status_code}")
                return {"target": self.target, "scan_type": "cms", "detected": []}
            
            html = resp.text
            headers = str(resp.headers).lower()
            full_text = html.lower() + " " + headers

            for cms, patterns in self.cms_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, full_text, re.IGNORECASE):
                        if cms not in self.detected:
                            self.detected.append(cms)
                            log_success(f"✅ Detected CMS: {cms}")
                        break

            if not self.detected:
                log_warning("No CMS detected. Might be custom-built.")
            else:
                log_success(f"Detection complete. Found: {', '.join(self.detected)}")
        except Exception as e:
            log_error(f"Error: {e}")

        return {"target": self.target, "scan_type": "cms", "detected": self.detected}
