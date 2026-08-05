#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
from core.logger import log_info, log_success, log_warning

class AdvancedAuto:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.detected_type = "unknown"
        self.recommended_modules = []

    def detect_target_type(self):
        """تشخیص خودکار نوع هدف"""
        log_info("Detecting target type...")
        
        # چک کردن صفحه اصلی
        try:
            resp = requests.get(self.target, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            html = resp.text.lower()
            headers = str(resp.headers).lower()
            
            # تشخیص CMS
            if "wp-content" in html or "wp-includes" in html:
                self.detected_type = "wordpress"
                self.recommended_modules = ["--cms-detect", "--cve-scan", "--sqli", "--xss", "--waf-detect"]
                log_success("Target detected as WordPress")
                return
            
            if "joomla" in html or "components/com_" in html:
                self.detected_type = "joomla"
                self.recommended_modules = ["--cms-detect", "--cve-scan", "--sqli", "--xss"]
                log_success("Target detected as Joomla")
                return
            
            if "drupal" in html or "sites/all" in html:
                self.detected_type = "drupal"
                self.recommended_modules = ["--cms-detect", "--cve-scan", "--sqli"]
                log_success("Target detected as Drupal")
                return
            
            # تشخیص API
            if "api" in self.target or "json" in headers or "application/json" in headers:
                self.detected_type = "api"
                self.recommended_modules = ["--param-discovery", "--jwt-scan", "--cors-check", "--rate-limit"]
                log_success("Target detected as API")
                return
            
            # تشخیص فروشگاه
            if "cart" in html or "checkout" in html or "product" in html:
                self.detected_type = "ecommerce"
                self.recommended_modules = ["--sqli", "--xss", "--idor-scan", "--business-logic"]
                log_success("Target detected as E-commerce")
                return
            
            # پیش‌فرض
            self.detected_type = "generic"
            self.recommended_modules = ["--headers-check", "--log-check", "--tech-detect", "--waf-detect"]
            log_success("Target detected as Generic website")
            
        except Exception as e:
            log_warning(f"Could not detect target type: {e}")
            self.detected_type = "unknown"
            self.recommended_modules = ["--headers-check", "--log-check"]

    def run(self):
        log_info(f"Starting Advanced Auto Scan on: {self.target}")
        self.detect_target_type()
        
        log_success(f"Detected Type: {self.detected_type}")
        log_info(f"Recommended Modules: {' '.join(self.recommended_modules)}")
        
        return {
            "target": self.target,
            "scan_type": "advanced_auto",
            "detected_type": self.detected_type,
            "recommended_modules": self.recommended_modules
        }
