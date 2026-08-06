#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class StaticAnalysis:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.results = []

    def check_javascript(self, url):
        """Analyze JavaScript files for vulnerabilities"""
        log_info(f"Analyzing JavaScript: {url}")
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False)
            if resp.status_code != 200:
                return

            content = resp.text

            # Check for dangerous functions
            patterns = {
                "eval()": r"eval\s*\(",
                "document.write()": r"document\.write\s*\(",
                "innerHTML": r"\.innerHTML\s*=",
                "outerHTML": r"\.outerHTML\s*=",
                "setTimeout() with string": r'setTimeout\s*\(\s*["\']',
                "setInterval() with string": r'setInterval\s*\(\s*["\']',
                "Function() constructor": r"new\s+Function\s*\(",
                "location.href": r'location\.href\s*=\s*["\']',
                "document.domain": r'document\.domain\s*=\s*["\']',
                "postMessage": r"\.postMessage\s*\(",
                "onmessage": r"\.onmessage\s*=",
                "addEventListener": r"\.addEventListener\s*\(",
            }

            for name, pattern in patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    self.results.append(
                        {
                            "file": url,
                            "type": "javascript_analysis",
                            "pattern": name,
                            "line": "found in file",
                        }
                    )
                    log_success(f"🔥 Found {name} in {url}")

        except Exception as e:
            if self.verbose:
                log_debug(f"Error analyzing {url}: {e}")

    def check_source_code(self, path):
        """Check for source code exposure"""
        log_info(f"Checking source code: {path}")
        try:
            url = f"{self.target}{path}"
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                self.results.append(
                    {
                        "file": url,
                        "type": "source_code_exposure",
                        "status": resp.status_code,
                    }
                )
                log_success(f"🔥 Source code exposed: {url}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error checking {path}: {e}")

    def run(self):
        log_info(f"Starting Static Analysis on: {self.target}")

        # Check for source code files
        source_files = [
            "/index.php",
            "/index.html",
            "/index.htm",
            "/.htaccess",
            "/.htpasswd",
            "/config.php",
            "/wp-config.php",
            "/settings.py",
            "/config.yml",
            "/config.yaml",
            "/composer.json",
            "/package.json",
            "/web.config",
            "/app.config",
            "/.env",
            "/.env.local",
            "/.env.backup",
        ]

        for file in source_files:
            self.check_source_code(file)

        # Check JavaScript files
        try:
            resp = requests.get(self.target, timeout=10)
            js_files = re.findall(
                r'<script[^>]*src=["\']([^"\']+\.js)[^"\']*["\']',
                resp.text,
                re.IGNORECASE,
            )
            for js_file in js_files:
                if not js_file.startswith("http"):
                    js_file = f"{self.target}/{js_file.lstrip('/')}"
                self.check_javascript(js_file)
        except Exception as e:
            log_error(f"Error fetching page: {e}")

        log_success(f"Static Analysis completed. Found {len(self.results)} issues.")
        return {
            "target": self.target,
            "scan_type": "static_analysis",
            "total_issues": len(self.results),
            "results": self.results,
        }
