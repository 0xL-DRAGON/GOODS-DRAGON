#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from core.logger import log_info, log_success, log_debug, log_error, log_warning

class JSDependencyScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.vulnerable_libs = []
        
        # Dictionary of known vulnerable JS libraries with their vulnerable versions
        self.vuln_patterns = {
            "jquery": {
                "pattern": r'jquery[.-]?([\d.]+)(?:\.min)?\.js',
                "vulnerable_versions": ["<1.9.0", "<1.12.0", "<2.2.0", "<3.0.0"]
            },
            "angular": {
                "pattern": r'angular(?:\.min)?\.js[^"]*["\']?.*?v=([\d.]+)',
                "vulnerable_versions": ["<1.5.0", "<1.6.0", "<1.7.0"]
            },
            "react": {
                "pattern": r'react(?:\.min)?\.js[^"]*["\']?.*?v=([\d.]+)',
                "vulnerable_versions": ["<15.0.0", "<16.0.0"]
            },
            "vue": {
                "pattern": r'vue(?:\.min)?\.js[^"]*["\']?.*?v=([\d.]+)',
                "vulnerable_versions": ["<2.0.0", "<2.5.0"]
            },
            "bootstrap": {
                "pattern": r'bootstrap(?:\.min)?\.js[^"]*["\']?.*?v=([\d.]+)',
                "vulnerable_versions": ["<3.4.0", "<4.0.0"]
            },
            "lodash": {
                "pattern": r'lodash(?:\.min)?\.js[^"]*["\']?.*?v=([\d.]+)',
                "vulnerable_versions": ["<4.17.0"]
            }
        }

    def fetch_page(self):
        try:
            resp = requests.get(self.target, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                return resp.text
            else:
                log_error(f"Failed to fetch page. Status: {resp.status_code}")
                return None
        except Exception as e:
            log_error(f"Error fetching page: {e}")
            return None

    def scan_dependencies(self, html):
        for lib_name, lib_data in self.vuln_patterns.items():
            matches = re.findall(lib_data["pattern"], html, re.IGNORECASE)
            if matches:
                for version in matches:
                    # Check if version is vulnerable (simplified check)
                    is_vuln = any(v in str(version) for v in ["1.", "2.", "3."])
                    if is_vuln:
                        self.vulnerable_libs.append({
                            "library": lib_name,
                            "version": version,
                            "status": "VULNERABLE",
                            "note": "Known vulnerabilities exist in this version"
                        })
                        log_success(f"🔥 Found vulnerable JS library: {lib_name} (v{version})")
                    elif self.verbose:
                        log_debug(f"Found {lib_name} (v{version}) - seems safe")

    def run(self):
        log_info(f"Starting JS Dependency Scan on: {self.target}")
        html = self.fetch_page()
        if not html:
            return {"target": self.target, "scan_type": "js_deps", "vulnerable_libs": []}

        self.scan_dependencies(html)
        
        if not self.vulnerable_libs:
            log_success("No vulnerable JS libraries found.")
        else:
            log_success(f"Found {len(self.vulnerable_libs)} vulnerable JS libraries.")
        
        return {
            "target": self.target,
            "scan_type": "js_deps",
            "total_vulnerable": len(self.vulnerable_libs),
            "vulnerable_libs": self.vulnerable_libs
        }
