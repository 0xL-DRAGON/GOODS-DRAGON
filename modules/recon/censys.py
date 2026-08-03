#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class CensysIntegration:
    def __init__(self, target, api_id=None, api_secret=None, verbose=False):
        self.target = target
        self.api_id = api_id
        self.api_secret = api_secret
        self.verbose = verbose
        self.results = {}

    def get_ip_info(self):
        """Get IP information from Censys"""
        if not self.api_id or not self.api_secret:
            log_warning("No Censys API credentials provided. Skipping.")
            return
        
        # Authenticate
        auth_url = "https://search.censys.io/api/v1/account"
        auth_resp = requests.get(auth_url, auth=(self.api_id, self.api_secret))
        if auth_resp.status_code != 200:
            log_error("Censys authentication failed")
            return
        
        # Search for IP
        search_url = f"https://search.censys.io/api/v1/search/ipv4?q={self.target}"
        try:
            resp = requests.get(search_url, auth=(self.api_id, self.api_secret))
            if resp.status_code == 200:
                data = resp.json()
                self.results['censys'] = {
                    "ip": self.target,
                    "results": data.get('results', [])
                }
                log_success(f"Censys data retrieved for {self.target}")
            else:
                log_error(f"Censys API error: {resp.status_code}")
        except Exception as e:
            log_error(f"Censys error: {e}")

    def run(self):
        log_info(f"Starting Censys Integration for: {self.target}")
        self.get_ip_info()
        log_success("Censys Integration completed.")
        return {
            "target": self.target,
            "scan_type": "censys",
            "results": self.results
        }
