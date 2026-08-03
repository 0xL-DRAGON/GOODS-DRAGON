#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class VersionScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.versions = []

    def scan_headers(self, headers):
        """Extract versions from HTTP headers"""
        version_patterns = {
            "Server": r'([a-zA-Z]+)/([\d.]+)',
            "X-Powered-By": r'([a-zA-Z]+)/([\d.]+)',
            "X-AspNet-Version": r'([\d.]+)',
            "X-AspNetMvc-Version": r'([\d.]+)',
            "X-Generator": r'([a-zA-Z]+) ([\d.]+)',
            "X-Drupal-Cache": r'Drupal ([\d.]+)',
            "X-Varnish": r'Varnish ([\d.]+)'
        }
        
        for header, pattern in version_patterns.items():
            if header in headers:
                value = headers[header]
                matches = re.findall(pattern, value, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        if len(match) == 2:
                            version = {
                                "software": match[0],
                                "version": match[1],
                                "source": header
                            }
                            self.versions.append(version)
                            log_success(f"Found {match[0]} v{match[1]} (from {header})")
                    else:
                        version = {
                            "software": header.replace("X-", ""),
                            "version": match,
                            "source": header
                        }
                        self.versions.append(version)
                        log_success(f"Found {header.replace('X-', '')} v{match} (from {header})")

    def scan_meta(self, html):
        """Extract versions from meta tags"""
        meta_patterns = {
            'generator': r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
            'version': r'<meta[^>]*name=["\']version["\'][^>]*content=["\']([^"\']+)["\']'
        }
        
        for name, pattern in meta_patterns.items():
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                version = {
                    "software": name,
                    "version": match,
                    "source": "meta_tag"
                }
                self.versions.append(version)
                log_success(f"Found {name} v{match} (from meta tag)")

    def scan_html_comments(self, html):
        """Extract versions from HTML comments"""
        comment_pattern = r'<!--[^>]*?([a-zA-Z]+)[^>]*?v(?:ersion)?[.:]?\s*([\d.]+)'
        matches = re.findall(comment_pattern, html, re.IGNORECASE)
        for software, version in matches:
            if software and version:
                version_info = {
                    "software": software.strip(),
                    "version": version.strip(),
                    "source": "html_comment"
                }
                self.versions.append(version_info)
                log_success(f"Found {software} v{version} (from HTML comment)")

    def scan_javascript(self, html):
        """Extract versions from JavaScript files"""
        js_pattern = r'<script[^>]*src=["\']([^"\']+\.js)[^"\']*["\']'
        js_files = re.findall(js_pattern, html, re.IGNORECASE)
        
        for js_file in js_files:
            if '?v=' in js_file or '?ver=' in js_file:
                version = js_file.split('?v=')[-1].split('&')[0] if '?v=' in js_file else js_file.split('?ver=')[-1].split('&')[0]
                version_info = {
                    "software": js_file.split('/')[-1].split('?')[0],
                    "version": version,
                    "source": "javascript_url",
                    "url": js_file
                }
                self.versions.append(version_info)
                log_success(f"Found {version_info['software']} v{version} (from JS URL)")

    def run(self):
        log_info(f"Starting Version Scanner on: {self.target}")
        
        try:
            resp = requests.get(self.target, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                log_error(f"Cannot fetch page. Status: {resp.status_code}")
                return {"target": self.target, "scan_type": "version_scanner", "versions": []}
            
            headers = resp.headers
            html = resp.text
            
            self.scan_headers(headers)
            self.scan_meta(html)
            self.scan_html_comments(html)
            self.scan_javascript(html)
            
        except Exception as e:
            log_error(f"Error: {e}")
        
        log_success(f"Version scan completed. Found {len(self.versions)} versions.")
        return {
            "target": self.target,
            "scan_type": "version_scanner",
            "total_found": len(self.versions),
            "versions": self.versions
        }
