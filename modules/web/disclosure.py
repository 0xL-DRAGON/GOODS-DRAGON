#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class InfoDisclosureScanner:
    def __init__(self, target, verbose=False, threads=20):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.threads = threads
        self.sensitive_files = [
            ".env",
            ".git/config",
            ".git/HEAD",
            "backup.sql",
            "backup.zip",
            "debug.log",
            "error.log",
            "phpinfo.php",
            "info.php",
            "test.php",
            "config.php",
            "wp-config.php",
            ".htaccess",
            ".htpasswd",
            "robots.txt",
            "sitemap.xml",
            "crossdomain.xml",
            "clientaccesspolicy.xml",
            ".DS_Store",
            "Thumbs.db",
            "wsdl.xml",
            "swagger.json",
            "openapi.json",
            "composer.json",
            "package.json",
            "yarn.lock",
            "Gemfile",
            "Gemfile.lock",
            "Dockerfile",
            "docker-compose.yml",
            "Jenkinsfile",
            ".travis.yml",
            ".gitlab-ci.yml",
        ]
        self.found = []

    def check_file(self, path):
        url = f"{self.target}/{path}"
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                # بررسی محتوای پاسخ برای تشخیص فایل واقعی (نه صفحه 404)
                content_type = resp.headers.get("Content-Type", "").lower()
                content_length = len(resp.text)

                # فیلتر کردن پاسخ‌های بی‌معنی (مثل صفحه 404 سفارشی)
                if (
                    content_length > 50
                    and "404" not in resp.text[:100]
                    and "not found" not in resp.text[:100].lower()
                ):
                    result = {
                        "url": url,
                        "status": resp.status_code,
                        "content_type": content_type,
                        "content_length": content_length,
                        "preview": resp.text[:200].replace("\n", " ").strip(),
                    }
                    self.found.append(result)
                    log_success(
                        f"✅ Found sensitive file: {url} ({content_type}, {content_length} bytes)"
                    )
                    return result
            elif self.verbose:
                log_debug(f"❌ {url} -> {resp.status_code}")
        except Exception as e:
            if self.verbose:
                log_debug(f"⚠️ Error checking {url}: {e}")
        return None

    def run(self):
        log_info(f"Starting Info Disclosure scan on: {self.target}")
        log_info(f"Checking {len(self.sensitive_files)} sensitive paths...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_file, path): path
                for path in self.sensitive_files
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    log_error(f"Error: {e}")

        log_success(
            f"Info Disclosure scan completed. Found {len(self.found)} sensitive files."
        )
        return {
            "target": self.target,
            "scan_type": "info_disclosure",
            "total_found": len(self.found),
            "files": self.found,
        }
