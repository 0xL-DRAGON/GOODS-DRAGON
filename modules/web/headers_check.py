#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.core.http_client import HTTPClient
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class SecurityHeadersChecker:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)

    def run(self):
        log_info(f"Starting Security Headers Check on: {self.target}")
        resp = self.client.get(self.target)
        
        if not resp:
            log_error(f"Cannot fetch page.")
            return {
                "target": self.target,
                "scan_type": "headers_check",
                "total_checked": 0,
                "present_count": 0,
                "headers": [],
                "error": "Failed to fetch page"
            }

        headers = resp.headers
        
        # لیست کامل هدرهای امنیتی به همراه توضیحات
        security_headers = {
            "Content-Security-Policy": {
                "short": "CSP",
                "description": "ممانعت از حملات XSS و تزریق کد"
            },
            "X-Frame-Options": {
                "short": "XFO",
                "description": "جلوگیری از Clickjacking"
            },
            "X-Content-Type-Options": {
                "short": "XCTO",
                "description": "جلوگیری از MIME Sniffing"
            },
            "Strict-Transport-Security": {
                "short": "HSTS",
                "description": "اجبار به استفاده از HTTPS"
            },
            "Referrer-Policy": {
                "short": "Referrer",
                "description": "مدیریت ارسال Referrer"
            },
            "X-XSS-Protection": {
                "short": "XXP",
                "description": "محافظت در برابر XSS (قدیمی)"
            },
            "Permissions-Policy": {
                "short": "Permissions",
                "description": "مدیریت دسترسی‌های مرورگر"
            },
            "Feature-Policy": {
                "short": "Feature",
                "description": "مدیریت ویژگی‌های مرورگر (قدیمی)"
            },
            "Cross-Origin-Embedder-Policy": {
                "short": "COEP",
                "description": "مدیریت Cross-Origin Embedding"
            },
            "Cross-Origin-Opener-Policy": {
                "short": "COOP",
                "description": "مدیریت Cross-Origin Opener"
            },
            "Cross-Origin-Resource-Policy": {
                "short": "CORP",
                "description": "مدیریت Cross-Origin Resource"
            }
        }

        results = []
        log_info("Checking security headers...")
        
        for header, info in security_headers.items():
            if header in headers:
                results.append({
                    "header": header,
                    "short": info["short"],
                    "present": True,
                    "value": headers[header],
                    "description": info["description"]
                })
                log_success(f"✅ {header}: {headers[header]}")
            else:
                results.append({
                    "header": header,
                    "short": info["short"],
                    "present": False,
                    "value": None,
                    "description": info["description"]
                })
                log_warning(f"❌ {header} is missing ({info['description']})")

        present_count = len([h for h in results if h["present"]])
        total_headers = len(results)
        
        log_success(f"Security Headers Check completed. {present_count}/{total_headers} headers present.")
        
        # رتبه‌بندی امنیت بر اساس تعداد هدرهای موجود
        security_score = "Unknown"
        if present_count >= 8:
            security_score = "Excellent"
        elif present_count >= 6:
            security_score = "Good"
        elif present_count >= 4:
            security_score = "Moderate"
        elif present_count >= 2:
            security_score = "Weak"
        else:
            security_score = "Poor"
        
        log_info(f"Security Score: {security_score} ({present_count}/{total_headers})")

        return {
            "target": self.target,
            "scan_type": "headers_check",
            "total_checked": total_headers,
            "present_count": present_count,
            "security_score": security_score,
            "headers": results,
            "raw_headers": dict(headers)
        }
