#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

from core.logger import log_info, log_success, log_warning
from modules.core.http_client import HTTPClient


class ThreatIntel:
    def __init__(self, target, verbose=False, api_keys=None):
        self.target = target
        self.verbose = verbose
        self.api_keys = api_keys or {}
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.results = {}

    def check_virustotal(self):
        """بررسی با VirusTotal"""
        if not self.api_keys.get("virustotal"):
            log_warning("VirusTotal API key not provided")
            return

        log_info("Checking VirusTotal...")
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.target}"
            headers = {"x-apikey": self.api_keys["virustotal"]}
            resp = self.client.get(url, headers=headers)
            if resp and resp.status_code == 200:
                data = resp.json()
                self.results["virustotal"] = data.get("data", {})
                log_success("VirusTotal check completed")
        except:
            pass

    def check_shodan(self):
        """بررسی با Shodan"""
        if not self.api_keys.get("shodan"):
            log_warning("Shodan API key not provided")
            return

        log_info("Checking Shodan...")
        try:
            url = f"https://api.shodan.io/shodan/host/{self.target}?key={self.api_keys['shodan']}"
            resp = self.client.get(url)
            if resp and resp.status_code == 200:
                self.results["shodan"] = resp.json()
                log_success("Shodan check completed")
        except:
            pass

    def check_abuseipdb(self):
        """بررسی با AbuseIPDB"""
        if not self.api_keys.get("abuseipdb"):
            log_warning("AbuseIPDB API key not provided")
            return

        log_info("Checking AbuseIPDB...")
        try:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.api_keys["abuseipdb"], "Accept": "application/json"}
            params = {"ipAddress": self.target}
            resp = self.client.get(url, headers=headers, params=params)
            if resp and resp.status_code == 200:
                self.results["abuseipdb"] = resp.json()
                log_success("AbuseIPDB check completed")
        except:
            pass

    def run(self):
        log_info(f"Starting Threat Intelligence on: {self.target}")
        self.check_virustotal()
        self.check_shodan()
        self.check_abuseipdb()
        log_success("Threat Intelligence completed.")
        return {
            "target": self.target,
            "scan_type": "threat_intel",
            "results": self.results,
        }
