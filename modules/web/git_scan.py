#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class GitScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.found = []

        # Common Git paths
        self.git_paths = [
            ".git/HEAD",
            ".git/config",
            ".git/index",
            ".git/description",
            ".git/logs/HEAD",
            ".git/refs/heads/master",
            ".git/refs/heads/main",
            ".git/objects/",
            ".git/info/exclude",
            ".git/hooks/",
            "wp-content/.git/HEAD",
            "wp-content/.git/config",
            "admin/.git/HEAD",
            "assets/.git/HEAD",
            "include/.git/HEAD",
            "src/.git/HEAD",
        ]

    def check_path(self, path):
        url = f"{self.target}/{path}"
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                result = {
                    "url": url,
                    "status": resp.status_code,
                    "content_length": len(resp.text),
                    "type": "git_exposed",
                }
                self.found.append(result)
                log_success(f"🔥 Found exposed Git path: {url}")
                return True
            elif self.verbose:
                log_debug(f"❌ {url} -> {resp.status_code}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error checking {url}: {e}")
        return False

    def run(self):
        log_info(f"Starting Git Repository Scan on: {self.target}")
        log_info(f"Checking {len(self.git_paths)} paths...")

        for path in self.git_paths:
            self.check_path(path)

        if self.found:
            log_success(f"Found {len(self.found)} exposed Git paths.")
        else:
            log_info("No exposed Git paths found.")

        return {
            "target": self.target,
            "scan_type": "git_scan",
            "total_found": len(self.found),
            "paths": self.found,
        }
