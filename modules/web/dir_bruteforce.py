#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class DirBruteforce:
    def __init__(self, target, wordlist_path="wordlists/dirs.txt", threads=30, verbose=False, extensions=["", ".php", ".html", ".bak"]):
        self.target = target.rstrip('/')
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.verbose = verbose
        self.extensions = extensions
        self.found = []
        self.lock = None  # Simple list append without lock for speed (since we are in ThreadPool)

    def load_wordlist(self):
        if not os.path.exists(self.wordlist_path):
            log_warning(f"Wordlist {self.wordlist_path} not found. Using default list.")
            return [
                "admin", "login", "wp-admin", "backup", "images", "css", "js", 
                "uploads", "files", "download", "tmp", "temp", "logs", "data",
                "config", "include", "src", "app", "vendor", "node_modules",
                "api", "v1", "v2", "test", "dev", "stage", "old", "new",
                "assets", "static", "media", "public", "private", "secure"
            ]
        with open(self.wordlist_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def check_dir(self, path):
        urls_to_check = []
        for ext in self.extensions:
            urls_to_check.append(f"{self.target}/{path}{ext}")
        
        for url in urls_to_check:
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False)
                if resp.status_code in [200, 403, 301, 302]:
                    result = {
                        "url": url,
                        "status": resp.status_code,
                        "content_length": len(resp.text)
                    }
                    self.found.append(result)
                    log_success(f"✅ Found: {url} [{resp.status_code}]")
                    return result
                elif self.verbose:
                    log_debug(f"❌ {url} -> {resp.status_code}")
            except Exception as e:
                if self.verbose:
                    log_debug(f"Error checking {url}: {e}")
        return None

    def run(self):
        log_info(f"Starting Directory Bruteforce on: {self.target}")
        wordlist = self.load_wordlist()
        log_info(f"Loaded {len(wordlist)} words.")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_dir, word): word for word in wordlist}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    log_error(f"Error: {e}")
        
        log_success(f"Directory bruteforce completed. Found {len(self.found)} entries.")
        return {"target": self.target, "scan_type": "dir_bruteforce", "total": len(self.found), "found": self.found}
