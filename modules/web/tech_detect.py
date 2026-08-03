#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import hashlib
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class TechnologyDetector:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.technologies = []

        # Favicon hashes for popular technologies
        self.favicon_hashes = {
            "8b3c3a4e1d5e2f6a3c4b5d6e7f8a9b0c": "WordPress",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": "Joomla",
            "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0": "Drupal",
            "f1e2d3c4b5a697887766554433221100": "Magento",
            "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7": "Laravel",
            "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3": "Bootstrap"
        }

        # Technology detection patterns
        self.tech_patterns = {
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
            "Laravel": [
                r'laravel',
                r'Laravel',
                r'vendor/laravel'
            ],
            "React": [
                r'react',
                r'React',
                r'__REACT_DEVTOOLS_GLOBAL_HOOK__'
            ],
            "Vue.js": [
                r'vue',
                r'Vue',
                r'__VUE__'
            ],
            "Angular": [
                r'angular',
                r'Angular',
                r'ng-',
                r'ng-app'
            ],
            "Bootstrap": [
                r'bootstrap',
                r'Bootstrap',
                r'cdn.jsdelivr.net/npm/bootstrap'
            ],
            "jQuery": [
                r'jquery',
                r'jQuery',
                r'cdnjs.cloudflare.com/ajax/libs/jquery'
            ]
        }

    def fetch_page(self):
        try:
            resp = requests.get(self.target, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                return resp.text, resp.headers
            else:
                log_error(f"Failed to fetch page. Status: {resp.status_code}")
                return None, None
        except Exception as e:
            log_error(f"Error fetching page: {e}")
            return None, None

    def detect_favicon(self, html):
        """Detect technology by favicon hash"""
        favicon_pattern = r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']'
        match = re.search(favicon_pattern, html, re.IGNORECASE)
        if match:
            favicon_url = match.group(1)
            if not favicon_url.startswith('http'):
                favicon_url = f"{self.target}/{favicon_url.lstrip('/')}"
            try:
                resp = requests.get(favicon_url, timeout=5)
                if resp.status_code == 200:
                    favicon_hash = hashlib.md5(resp.content).hexdigest()
                    if favicon_hash in self.favicon_hashes:
                        tech = self.favicon_hashes[favicon_hash]
                        self.technologies.append({"name": tech, "type": "CMS (Favicon)"})
                        log_success(f"Found {tech} via favicon hash")
            except:
                pass

    def detect_from_meta(self, html):
        """Detect technology from meta tags"""
        meta_pattern = r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']'
        matches = re.findall(meta_pattern, html, re.IGNORECASE)
        for content in matches:
            tech = content.strip()
            if tech and tech not in [t["name"] for t in self.technologies]:
                self.technologies.append({"name": tech, "type": "Meta Generator"})
                log_success(f"Found {tech} via meta generator")

    def detect_from_headers(self, headers):
        """Detect technology from HTTP headers"""
        server = headers.get('Server', '')
        if 'Apache' in server:
            self.technologies.append({"name": "Apache", "type": "Web Server"})
        if 'nginx' in server:
            self.technologies.append({"name": "Nginx", "type": "Web Server"})
        if 'IIS' in server:
            self.technologies.append({"name": "IIS", "type": "Web Server"})
        if 'Cloudflare' in headers.get('CF-RAY', ''):
            self.technologies.append({"name": "Cloudflare", "type": "CDN"})
        if 'x-powered-by' in headers:
            tech = headers['x-powered-by']
            if 'PHP' in tech:
                self.technologies.append({"name": "PHP", "type": "Language"})
            if 'ASP.NET' in tech:
                self.technologies.append({"name": "ASP.NET", "type": "Language"})

    def detect_from_html(self, html):
        """Detect technology from HTML content"""
        for tech, patterns in self.tech_patterns.items():
            if tech in [t["name"] for t in self.technologies]:
                continue
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    self.technologies.append({"name": tech, "type": "Framework/CMS"})
                    log_success(f"Found {tech} via HTML pattern")
                    break

    def run(self):
        log_info(f"Starting Technology Detection on: {self.target}")
        
        html, headers = self.fetch_page()
        if not html:
            return {"target": self.target, "scan_type": "tech_detect", "technologies": []}

        # Run all detection methods
        self.detect_from_headers(headers)
        self.detect_from_html(html)
        self.detect_from_meta(html)
        self.detect_favicon(html)

        # Remove duplicates
        seen = set()
        unique_techs = []
        for tech in self.technologies:
            key = (tech["name"], tech["type"])
            if key not in seen:
                seen.add(key)
                unique_techs.append(tech)
        self.technologies = unique_techs

        if not self.technologies:
            log_warning("No technologies detected.")
        else:
            log_success(f"Found {len(self.technologies)} technologies:")
            for tech in self.technologies:
                log_success(f"  - {tech['name']} ({tech['type']})")

        return {
            "target": self.target,
            "scan_type": "tech_detect",
            "total_found": len(self.technologies),
            "technologies": self.technologies
        }
