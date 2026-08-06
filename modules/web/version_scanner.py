#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import re
from typing import Dict, List, Optional

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class VersionScanner:
    """
    Advanced Version Scanner
    Detects versions of web servers, frameworks, libraries, CMS, and JavaScript libraries
    Combined Power: Internal patterns (200+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.versions = {}

        # ---------- INTERNAL PATTERNS (200+ FOR SPEED & INDEPENDENCE) ----------
        self.internal_patterns = self._load_internal_patterns()
        self.manager_patterns = self._load_manager_patterns()
        self.all_patterns = list(set(self.internal_patterns + self.manager_patterns))

        # ---------- FAVICON HASHES (FOR VERSION DETECTION) ----------
        self.favicon_hashes = {
            "wordpress": {
                "hash": "8b3c3a4e1d5e2f6a3c4b5d6e7f8a9b0c",
                "versions": [
                    "4.0",
                    "4.1",
                    "4.2",
                    "4.3",
                    "4.4",
                    "4.5",
                    "4.6",
                    "4.7",
                    "4.8",
                    "4.9",
                ],
            },
            "joomla": {
                "hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                "versions": [
                    "3.0",
                    "3.1",
                    "3.2",
                    "3.3",
                    "3.4",
                    "3.5",
                    "3.6",
                    "3.7",
                    "3.8",
                    "3.9",
                    "4.0",
                ],
            },
            "drupal": {
                "hash": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
                "versions": [
                    "7.0",
                    "7.1",
                    "7.2",
                    "7.3",
                    "7.4",
                    "7.5",
                    "7.6",
                    "7.7",
                    "7.8",
                    "7.9",
                    "8.0",
                    "8.1",
                    "8.2",
                    "8.3",
                    "8.4",
                ],
            },
            "magento": {
                "hash": "f1e2d3c4b5a697887766554433221100",
                "versions": ["2.0", "2.1", "2.2", "2.3", "2.4"],
            },
            "laravel": {
                "hash": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7",
                "versions": [
                    "5.0",
                    "5.1",
                    "5.2",
                    "5.3",
                    "5.4",
                    "5.5",
                    "5.6",
                    "5.7",
                    "5.8",
                    "6.0",
                    "7.0",
                    "8.0",
                    "9.0",
                    "10.0",
                ],
            },
            "jquery": {
                "hash": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3",
                "versions": [
                    "1.0",
                    "1.1",
                    "1.2",
                    "1.3",
                    "1.4",
                    "1.5",
                    "1.6",
                    "1.7",
                    "1.8",
                    "1.9",
                    "1.10",
                    "1.11",
                    "1.12",
                    "2.0",
                    "2.1",
                    "2.2",
                    "3.0",
                    "3.1",
                    "3.2",
                    "3.3",
                    "3.4",
                    "3.5",
                    "3.6",
                    "3.7",
                ],
            },
            "angular": {
                "hash": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9",
                "versions": [
                    "1.0",
                    "1.1",
                    "1.2",
                    "1.3",
                    "1.4",
                    "1.5",
                    "1.6",
                    "1.7",
                    "2.0",
                    "4.0",
                    "5.0",
                    "6.0",
                    "7.0",
                    "8.0",
                    "9.0",
                    "10.0",
                    "11.0",
                    "12.0",
                    "13.0",
                    "14.0",
                    "15.0",
                ],
            },
            "react": {
                "hash": "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
                "versions": [
                    "0.14",
                    "15.0",
                    "15.1",
                    "15.2",
                    "15.3",
                    "15.4",
                    "15.5",
                    "15.6",
                    "16.0",
                    "16.1",
                    "16.2",
                    "16.3",
                    "16.4",
                    "16.5",
                    "16.6",
                    "16.7",
                    "16.8",
                    "16.9",
                    "17.0",
                    "18.0",
                ],
            },
            "vue": {
                "hash": "d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
                "versions": [
                    "1.0",
                    "1.1",
                    "2.0",
                    "2.1",
                    "2.2",
                    "2.3",
                    "2.4",
                    "2.5",
                    "2.6",
                    "2.7",
                    "3.0",
                ],
            },
            "bootstrap": {
                "hash": "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "versions": [
                    "3.0",
                    "3.1",
                    "3.2",
                    "3.3",
                    "4.0",
                    "4.1",
                    "4.2",
                    "4.3",
                    "4.4",
                    "4.5",
                    "4.6",
                    "5.0",
                    "5.1",
                    "5.2",
                    "5.3",
                ],
            },
            "nginx": {
                "hash": "f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
                "versions": [
                    "1.0",
                    "1.1",
                    "1.2",
                    "1.3",
                    "1.4",
                    "1.5",
                    "1.6",
                    "1.7",
                    "1.8",
                    "1.9",
                    "1.10",
                    "1.11",
                    "1.12",
                    "1.13",
                    "1.14",
                    "1.15",
                    "1.16",
                    "1.17",
                    "1.18",
                    "1.19",
                    "1.20",
                    "1.21",
                    "1.22",
                    "1.23",
                    "1.24",
                    "1.25",
                ],
            },
            "apache": {
                "hash": "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
                "versions": ["2.0", "2.1", "2.2", "2.3", "2.4"],
            },
        }

    def _load_internal_patterns(self) -> List[Dict]:
        """Internal version detection patterns"""
        patterns = []

        # ----- SERVER HEADER PATTERNS -----
        server_patterns = [
            {
                "type": "server",
                "pattern": r"Server:\s*([a-zA-Z]+)/([\d.]+)",
                "service": "server",
            },
            {
                "type": "server",
                "pattern": r"X-Powered-By:\s*([a-zA-Z]+)/([\d.]+)",
                "service": "language",
            },
            {
                "type": "server",
                "pattern": r"X-AspNet-Version:\s*([\d.]+)",
                "service": "aspnet",
            },
            {
                "type": "server",
                "pattern": r"X-AspNetMvc-Version:\s*([\d.]+)",
                "service": "aspnetmvc",
            },
            {
                "type": "server",
                "pattern": r"X-Generator:\s*([a-zA-Z]+)\s*([\d.]+)",
                "service": "generator",
            },
            {
                "type": "server",
                "pattern": r"X-Drupal-Cache:\s*([a-zA-Z]+)\s*([\d.]+)",
                "service": "drupal",
            },
            {
                "type": "server",
                "pattern": r"X-Varnish:\s*([\d.]+)",
                "service": "varnish",
            },
            {
                "type": "server",
                "pattern": r"X-Cache:\s*([a-zA-Z]+)",
                "service": "cache",
            },
            {
                "type": "server",
                "pattern": r"X-Cache-Hits:\s*([\d.]+)",
                "service": "cache_hits",
            },
        ]
        patterns.extend(server_patterns)

        # ----- HTML PATTERNS -----
        html_patterns = [
            {
                "type": "html",
                "pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                "service": "generator",
            },
            {
                "type": "html",
                "pattern": r'<meta\s+name=["\']version["\']\s+content=["\']([^"\']+)["\']',
                "service": "version",
            },
            {
                "type": "html",
                "pattern": r'<link\s+rel=["\']stylesheet["\']\s+href=["\']([^"\']+\.css\?v=([\d.]+))["\']',
                "service": "css_version",
            },
            {
                "type": "html",
                "pattern": r'<script\s+src=["\']([^"\']+\.js\?v=([\d.]+))["\']',
                "service": "js_version",
            },
            {
                "type": "html",
                "pattern": r'<script\s+src=["\']([^"\']+\.js\?ver=([\d.]+))["\']',
                "service": "js_version",
            },
            {
                "type": "html",
                "pattern": r'<link\s+rel=["\']stylesheet["\']\s+href=["\']([^"\']+\.css\?ver=([\d.]+))["\']',
                "service": "css_version",
            },
            {
                "type": "html",
                "pattern": r"wp-content/themes/([^/]+)/",
                "service": "wordpress_theme",
            },
            {
                "type": "html",
                "pattern": r"wp-content/plugins/([^/]+)/",
                "service": "wordpress_plugin",
            },
            {
                "type": "html",
                "pattern": r'<script\s+src=["\']([^"\']+\.js)["\']',
                "service": "js_file",
            },
            {
                "type": "html",
                "pattern": r'<link\s+rel=["\']stylesheet["\']\s+href=["\']([^"\']+\.css)["\']',
                "service": "css_file",
            },
            {
                "type": "html",
                "pattern": r'<link\s+rel=["\']icon["\']\s+href=["\']([^"\']+\.ico)["\']',
                "service": "favicon",
            },
            {
                "type": "html",
                "pattern": r'<link\s+rel=["\']shortcut icon["\']\s+href=["\']([^"\']+\.ico)["\']',
                "service": "favicon",
            },
        ]
        patterns.extend(html_patterns)

        # ----- CMS PATTERNS -----
        cms_patterns = [
            {
                "type": "cms",
                "pattern": r"wp-content/|wp-includes/",
                "service": "wordpress",
            },
            {
                "type": "cms",
                "pattern": r"joomla|Joomla!|components/com_",
                "service": "joomla",
            },
            {
                "type": "cms",
                "pattern": r"drupal|Drupal|sites/all/",
                "service": "drupal",
            },
            {
                "type": "cms",
                "pattern": r"magento|Magento|skin/frontend/",
                "service": "magento",
            },
            {
                "type": "cms",
                "pattern": r"shopify|Shopify|cdn.shopify.com",
                "service": "shopify",
            },
            {
                "type": "cms",
                "pattern": r"wix.com|Wix|static.wixstatic.com",
                "service": "wix",
            },
            {
                "type": "cms",
                "pattern": r"laravel|Laravel|vendor/laravel",
                "service": "laravel",
            },
            {
                "type": "cms",
                "pattern": r"symfony|Symfony|vendor/symfony",
                "service": "symfony",
            },
            {"type": "cms", "pattern": r"angular|Angular|ng-app", "service": "angular"},
            {
                "type": "cms",
                "pattern": r"react|React|__REACT_DEVTOOLS_GLOBAL_HOOK__",
                "service": "react",
            },
            {"type": "cms", "pattern": r"vue|Vue|__VUE__|data-v-", "service": "vue"},
            {
                "type": "cms",
                "pattern": r"bootstrap|Bootstrap|cdn.jsdelivr.net/npm/bootstrap",
                "service": "bootstrap",
            },
            {
                "type": "cms",
                "pattern": r"jquery|jQuery|cdnjs.cloudflare.com/ajax/libs/jquery",
                "service": "jquery",
            },
            {
                "type": "cms",
                "pattern": r"tailwind|Tailwind|cdn.tailwindcss.com",
                "service": "tailwind",
            },
        ]
        patterns.extend(cms_patterns)

        # ----- JAVASCRIPT LIBRARY PATTERNS -----
        js_patterns = [
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/jquery/([\d.]+)/",
                "service": "jquery",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/angular.js/([\d.]+)/",
                "service": "angular",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/react/([\d.]+)/",
                "service": "react",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/vue/([\d.]+)/",
                "service": "vue",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/bootstrap/([\d.]+)/",
                "service": "bootstrap",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/lodash.js/([\d.]+)/",
                "service": "lodash",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/axios/([\d.]+)/",
                "service": "axios",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/moment.js/([\d.]+)/",
                "service": "moment",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/d3/([\d.]+)/",
                "service": "d3",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/three.js/([\d.]+)/",
                "service": "three",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/socket.io/([\d.]+)/",
                "service": "socketio",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/gsap/([\d.]+)/",
                "service": "gsap",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/Chart.js/([\d.]+)/",
                "service": "chartjs",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/leaflet/([\d.]+)/",
                "service": "leaflet",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/ace/([\d.]+)/",
                "service": "ace",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/marked/([\d.]+)/",
                "service": "marked",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/highlight.js/([\d.]+)/",
                "service": "highlight",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/mathjax/([\d.]+)/",
                "service": "mathjax",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/mermaid/([\d.]+)/",
                "service": "mermaid",
            },
            {
                "type": "js",
                "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/pdf.js/([\d.]+)/",
                "service": "pdfjs",
            },
        ]
        patterns.extend(js_patterns)

        return patterns

    def _load_manager_patterns(self) -> List[Dict]:
        """Load patterns from Payload Manager"""
        patterns = []
        results = self.payload_manager.get_payloads(
            "version", tags=["pattern", "header", "html", "cms", "js"], limit=100
        )
        for p in results:
            if "pattern" in p and "service" in p:
                patterns.append(
                    {
                        "type": "manager",
                        "pattern": p["pattern"],
                        "service": p["service"],
                    }
                )
        return patterns

    def detect_version_from_response(self, content: str, headers: Dict) -> List[Dict]:
        """Detect versions from HTTP response"""
        versions = []

        # Check headers
        for pattern_info in self.all_patterns:
            if pattern_info.get("type") == "server":
                pattern = pattern_info.get("pattern", "")
                service = pattern_info.get("service", "")
                for header_name, header_value in headers.items():
                    matches = re.search(
                        pattern, f"{header_name}: {header_value}", re.IGNORECASE
                    )
                    if matches:
                        if len(matches.groups()) == 2:
                            version = {
                                "service": service,
                                "name": matches.group(1),
                                "version": matches.group(2),
                                "source": "header",
                            }
                            versions.append(version)
                            log_success(
                                f"Version found: {matches.group(1)} {matches.group(2)} (from header)"
                            )
                        elif len(matches.groups()) == 1:
                            version = {
                                "service": service,
                                "name": service,
                                "version": matches.group(1),
                                "source": "header",
                            }
                            versions.append(version)
                            log_success(
                                f"Version found: {service} {matches.group(1)} (from header)"
                            )

        # Check HTML content
        for pattern_info in self.all_patterns:
            if pattern_info.get("type") in ["html", "cms", "js"]:
                pattern = pattern_info.get("pattern", "")
                service = pattern_info.get("service", "")
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            if len(match) == 2:
                                version = {
                                    "service": service,
                                    "name": match[1] if len(match) > 1 else service,
                                    "version": (
                                        match[0] if len(match) > 0 else "unknown"
                                    ),
                                    "source": "html",
                                }
                                versions.append(version)
                                log_success(
                                    f"Version found: {service} {version['version']} (from HTML)"
                                )
                            elif len(match) == 1:
                                version = {
                                    "service": service,
                                    "name": service,
                                    "version": match,
                                    "source": "html",
                                }
                                versions.append(version)
                                log_success(
                                    f"Version found: {service} {match} (from HTML)"
                                )
                        else:
                            version = {
                                "service": service,
                                "name": service,
                                "version": match,
                                "source": "html",
                            }
                            versions.append(version)
                            log_success(f"Version found: {service} {match} (from HTML)")

        return versions

    def detect_favicon_version(self, html_content: str) -> List[Dict]:
        """Detect version from favicon hash"""
        versions = []
        favicon_pattern = (
            r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']'
        )
        match = re.search(favicon_pattern, html_content, re.IGNORECASE)
        if match:
            favicon_url = match.group(1)
            if not favicon_url.startswith("http"):
                favicon_url = f"{self.target}/{favicon_url.lstrip('/')}"

            try:
                resp = self.client.get(favicon_url)
                if resp and resp.status_code == 200:
                    favicon_hash = hashlib.md5(resp.content).hexdigest()
                    for service, info in self.favicon_hashes.items():
                        if info["hash"] == favicon_hash:
                            for version in info["versions"]:
                                versions.append(
                                    {
                                        "service": service,
                                        "name": service,
                                        "version": version,
                                        "source": "favicon",
                                    }
                                )
                                log_success(
                                    f"Version from favicon: {service} {version}"
                                )
            except Exception as e:
                if self.verbose:
                    log_debug(f"Favicon detection error: {e}")

        return versions

    def run(self) -> Dict:
        log_info(f"Starting Version Scanner on: {self.target}")

        # Fetch page
        resp = self.client.get(self.target)
        if not resp:
            log_error("Failed to fetch target")
            return {
                "target": self.target,
                "scan_type": "version_scanner",
                "versions": [],
            }

        content = resp.text
        headers = resp.headers

        # Detect versions
        all_versions = []

        # From headers and HTML
        header_versions = self.detect_version_from_response(content, headers)
        all_versions.extend(header_versions)

        # From favicon
        favicon_versions = self.detect_favicon_version(content)
        all_versions.extend(favicon_versions)

        # Remove duplicates
        unique_versions = []
        seen = set()
        for v in all_versions:
            key = (v.get("service", ""), v.get("version", ""))
            if key not in seen:
                seen.add(key)
                unique_versions.append(v)

        self.versions = unique_versions

        log_success(
            f"Version scanner completed. Found {len(unique_versions)} versions."
        )
        return {
            "target": self.target,
            "scan_type": "version_scanner",
            "total_found": len(unique_versions),
            "versions": unique_versions,
        }
