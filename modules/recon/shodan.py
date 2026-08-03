#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class ShodanIntegration:
    def __init__(self, target, api_key=None, verbose=False):
        self.target = target
        self.api_key = api_key
        self.verbose = verbose
        self.results = {}

    def get_ip_info(self):
        """Get IP information from Shodan"""
        if not self.api_key:
            log_warning("No Shodan API key provided. Using free API.")
            url = f"https://internetdb.shodan.io/{self.target}"
        else:
            url = f"https://api.shodan.io/shodan/host/{self.target}?key={self.api_key}"
        
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                self.results['shodan'] = {
                    "ip": data.get('ip', 'N/A'),
                    "country": data.get('country_name', 'N/A'),
                    "isp": data.get('isp', 'N/A'),
                    "org": data.get('org', 'N/A'),
                    "os": data.get('os', 'N/A'),
                    "ports": data.get('ports', []),
                    "hostnames": data.get('hostnames', [])
                }
                log_success(f"Shodan data retrieved for {self.target}")
            else:
                log_error(f"Shodan API error: {resp.status_code}")
        except Exception as e:
            log_error(f"Shodan error: {e}")

    def run(self):
        log_info(f"Starting Shodan Integration for: {self.target}")
        self.get_ip_info()
        log_success("Shodan Integration completed.")
        return {
            "target": self.target,
            "scan_type": "shodan",
            "results": self.results
        }
