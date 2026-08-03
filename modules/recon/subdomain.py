# -*- coding: utf-8 -*-
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import log_info, log_success, log_warning, log_error, log_debug
from core.network import resolve_domain, check_http_status

class SubdomainFinder:
    def __init__(self, domain, wordlist_path="wordlists/subdomains.txt", threads=30, verbose=False):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.verbose = verbose
        self.found_subdomains = []
        self.lock = threading.Lock()
        self.total_tested = 0

    def load_wordlist(self):
        if not os.path.exists(self.wordlist_path):
            log_warning(f"Wordlist {self.wordlist_path} not found. Using default list.")
            return ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "cpanel", "admin", "blog", "dev", "vpn", "mysql", "api", "cdn", "git", "store", "help", "server"]
        with open(self.wordlist_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def check_subdomain(self, sub):
        full_domain = f"{sub}.{self.domain}"
        with self.lock:
            self.total_tested += 1
            if self.total_tested % 20 == 0:
                log_info(f"Tested: {self.total_tested} - Found: {len(self.found_subdomains)}")

        ip = resolve_domain(full_domain)
        if not ip:
            if self.verbose:
                log_debug(f"❌ {full_domain} -> DNS Failed")
            return None

        url, status = check_http_status(full_domain)
        result = {"subdomain": full_domain, "ip": ip, "url": url, "status": status, "alive": url is not None}
        with self.lock:
            self.found_subdomains.append(result)
            if url and status:
                log_success(f"✅ {full_domain} -> {url} [{status}] (IP: {ip})")
            elif self.verbose:
                log_debug(f"ℹ️ {full_domain} -> DNS: {ip} (HTTP Inactive)")
        return result

    def run(self):
        log_info(f"Starting subdomain enumeration for: {self.domain}")
        subdomains_list = self.load_wordlist()
        log_info(f"Loaded {len(subdomains_list)} words.")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in subdomains_list}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    log_error(f"Error: {e}")

        alive = [s for s in self.found_subdomains if s.get("alive")]
        log_success(f"Scan completed. Total: {len(self.found_subdomains)} - Alive: {len(alive)}")
        return {"target": self.domain, "total_found": len(self.found_subdomains), "subdomains": self.found_subdomains}
