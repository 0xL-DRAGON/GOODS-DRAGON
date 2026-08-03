#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class BrokenLinkChecker:
    def __init__(self, target, threads=20, verbose=False):
        self.target = target.rstrip('/')
        self.threads = threads
        self.verbose = verbose
        self.broken_links = []
        self.checked_links = set()

    def get_links(self, html):
        """Extract all links from HTML"""
        pattern = r'href=["\'](.*?)["\']'
        links = re.findall(pattern, html, re.IGNORECASE)
        # Filter out empty and invalid links
        valid_links = []
        for link in links:
            if link and not link.startswith(('#', 'mailto:', 'tel:', 'javascript:', 'data:')):
                if link.startswith('http'):
                    valid_links.append(link)
                else:
                    full_url = urljoin(self.target, link)
                    valid_links.append(full_url)
        return valid_links

    def check_link(self, url):
        """Check if a link is broken"""
        if url in self.checked_links:
            return
        self.checked_links.add(url)
        
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
            if resp.status_code >= 400:
                result = {
                    "url": url,
                    "status": resp.status_code,
                    "type": "broken"
                }
                self.broken_links.append(result)
                log_warning(f"💔 Broken link: {url} [{resp.status_code}]")
            elif self.verbose:
                log_debug(f"✅ Valid link: {url} [{resp.status_code}]")
        except requests.exceptions.ConnectionError:
            result = {
                "url": url,
                "status": "ConnectionError",
                "type": "broken"
            }
            self.broken_links.append(result)
            log_warning(f"💔 Connection error: {url}")
        except requests.exceptions.Timeout:
            result = {
                "url": url,
                "status": "Timeout",
                "type": "broken"
            }
            self.broken_links.append(result)
            log_warning(f"💔 Timeout: {url}")
        except Exception as e:
            result = {
                "url": url,
                "status": str(e),
                "type": "broken"
            }
            self.broken_links.append(result)
            log_warning(f"💔 Error: {url} - {e}")

    def run(self):
        log_info(f"Starting Broken Link Checker on: {self.target}")
        
        try:
            resp = requests.get(self.target, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                log_error(f"Cannot fetch page. Status: {resp.status_code}")
                return {"target": self.target, "scan_type": "broken_link", "broken_links": []}
            
            links = self.get_links(resp.text)
            log_info(f"Found {len(links)} links to check...")
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.check_link, link): link for link in links}
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        log_error(f"Error checking link: {e}")
            
        except Exception as e:
            log_error(f"Error: {e}")
        
        log_success(f"Broken link check completed. Found {len(self.broken_links)} broken links.")
        return {
            "target": self.target,
            "scan_type": "broken_link",
            "total_broken": len(self.broken_links),
            "broken_links": self.broken_links
        }
