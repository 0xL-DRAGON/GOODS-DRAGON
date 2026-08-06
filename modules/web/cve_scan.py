#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime, timedelta

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class CVEScanner:
    def __init__(self, target, cms_data=None, tech_data=None, verbose=False):
        self.target = target
        self.cms_data = cms_data if cms_data else {}
        self.tech_data = tech_data if tech_data else {}
        self.verbose = verbose
        self.vulnerabilities = []
        self.cve_cache = {}

    def fetch_cve_from_nvd(self, tech_name, version=None):
        """Fetch CVEs from NVD API for a given technology"""
        try:
            # Search for CPEs related to the technology
            query = tech_name.lower()
            if version:
                query += f" {version}"

            url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={query}&resultsPerPage=10"
            resp = requests.get(url, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                cpes = []
                for item in data.get("results", {}).get("products", []):
                    cpe = item.get("cpe", {})
                    if cpe:
                        cpes.append(cpe.get("cpeName", ""))

                # Fetch CVEs for these CPEs
                for cpe in cpes[:5]:
                    cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}&resultsPerPage=5"
                    cve_resp = requests.get(cve_url, timeout=15)
                    if cve_resp.status_code == 200:
                        cve_data = cve_resp.json()
                        for vuln in cve_data.get("vulnerabilities", []):
                            cve_id = vuln.get("cve", {}).get("id", "N/A")
                            metrics = vuln.get("cve", {}).get("metrics", {})
                            severity = "N/A"
                            if metrics:
                                if "cvssMetricV31" in metrics:
                                    severity = (
                                        metrics["cvssMetricV31"][0]
                                        .get("cvssData", {})
                                        .get("baseSeverity", "N/A")
                                    )
                                elif "cvssMetricV2" in metrics:
                                    severity = metrics["cvssMetricV2"][0].get(
                                        "baseSeverity", "N/A"
                                    )

                            description = (
                                vuln.get("cve", {})
                                .get("descriptions", [{}])[0]
                                .get("value", "N/A")
                            )

                            if cve_id != "N/A":
                                self.vulnerabilities.append(
                                    {
                                        "technology": tech_name,
                                        "version": version or "Unknown",
                                        "cve": cve_id,
                                        "severity": severity,
                                        "description": description[:200],
                                    }
                                )
                                log_success(
                                    f"🔥 Found CVE: {cve_id} for {tech_name} (Severity: {severity})"
                                )
            else:
                if self.verbose:
                    log_debug(
                        f"NVD API returned status {resp.status_code} for {tech_name}"
                    )
        except Exception as e:
            if self.verbose:
                log_debug(f"Error fetching CVEs from NVD: {e}")

    def check_techs(self):
        """Check CVEs for detected technologies"""
        # Check CMS
        if self.cms_data and isinstance(self.cms_data, dict):
            cms_name = (
                self.cms_data.get("detected", ["Unknown"])[0]
                if self.cms_data.get("detected")
                else None
            )
            if cms_name:
                # Extract version from data if available
                version = None
                for key, value in self.cms_data.items():
                    if "version" in key.lower():
                        version = value
                        break
                self.fetch_cve_from_nvd(cms_name, version)

        # Check Tech
        if self.tech_data and isinstance(self.tech_data, dict):
            techs = self.tech_data.get("technologies", [])
            for tech in techs:
                if isinstance(tech, dict):
                    name = tech.get("name", "")
                    if name:
                        self.fetch_cve_from_nvd(name)

        # Check JavaScript libraries
        if self.tech_data and isinstance(self.tech_data, dict):
            js_libs = self.tech_data.get("js_deps", [])
            for lib in js_libs:
                if isinstance(lib, dict):
                    name = lib.get("library", "")
                    version = lib.get("version", "")
                    if name:
                        self.fetch_cve_from_nvd(name, version)

    def run(self):
        log_info(f"Starting CVE Vulnerability Scan on: {self.target}")
        self.check_techs()

        if not self.vulnerabilities:
            log_success("No known CVEs found for detected technologies.")
        else:
            log_success(f"Found {len(self.vulnerabilities)} potential vulnerabilities.")

        return {
            "target": self.target,
            "scan_type": "cve_scan",
            "total_vulns": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
        }
