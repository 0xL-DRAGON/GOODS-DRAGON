#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import random
import threading
from typing import List, Dict, Optional, Tuple
from modules.core.http_client import HTTPClient
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class RateLimitChecker:
    """
    Advanced Rate Limit Scanner
    Detects rate limiting thresholds, bypass techniques, and misconfigurations
    Supports: Request counting, Time-based detection, Response header analysis,
              IP rotation simulation, Burst testing, Bypass techniques
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=10, retries=2, verbose=verbose)
        self.results = []
        self.rate_limit_detected = False
        self.limit_threshold = 0
        self.time_window = 0
        self.bypass_techniques = []

        # Common rate limit headers to check
        self.rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'X-RateLimit-ResetTime',
            'Retry-After',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset',
            'X-RateLimit-RequestLimit',
            'X-RateLimit-Request-Allowed',
            'X-RateLimit-Request-Reset',
            'X-RateLimit-Request-Limit',
            'X-RateLimit-Request-Remaining',
            'X-RateLimit-Request-ResetTime',
            'X-RateLimit-Request-Reset'
        ]

        # Bypass techniques to test
        self.bypass_payloads = [
            # IP rotation simulation
            {"type": "ip_rotation", "value": "X-Forwarded-For: 127.0.0.1"},
            {"type": "ip_rotation", "value": "X-Real-IP: 127.0.0.1"},
            {"type": "ip_rotation", "value": "X-Originating-IP: 127.0.0.1"},
            {"type": "ip_rotation", "value": "X-Client-IP: 127.0.0.1"},
            {"type": "ip_rotation", "value": "X-Remote-IP: 127.0.0.1"},
            {"type": "ip_rotation", "value": "X-Forwarded-Host: 127.0.0.1"},
            {"type": "ip_rotation", "value": "X-Forwarded-Proto: http"},
            {"type": "ip_rotation", "value": "X-Forwarded-Port: 80"},
            {"type": "ip_rotation", "value": "X-Forwarded-For: 192.168.1.1"},
            {"type": "ip_rotation", "value": "X-Forwarded-For: 10.0.0.1"},
            {"type": "ip_rotation", "value": "X-Forwarded-For: 172.16.0.1"},
            {"type": "ip_rotation", "value": "X-Forwarded-For: 8.8.8.8"},
            {"type": "ip_rotation", "value": "X-Forwarded-For: 1.1.1.1"},
            {"type": "ip_rotation", "value": "X-Forwarded-For: 100.64.0.1"},
            # User-Agent rotation
            {"type": "ua_rotation", "value": "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)"},
            {"type": "ua_rotation", "value": "User-Agent: Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
            {"type": "ua_rotation", "value": "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"},
            {"type": "ua_rotation", "value": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},
            {"type": "ua_rotation", "value": "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},
            {"type": "ua_rotation", "value": "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},
            {"type": "ua_rotation", "value": "User-Agent: Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0"},
            # Parameter pollution
            {"type": "param_pollution", "value": "&limit=9999"},
            {"type": "param_pollution", "value": "&page=1&limit=9999"},
            {"type": "param_pollution", "value": "&offset=0&limit=9999"},
            {"type": "param_pollution", "value": "&size=9999"},
            {"type": "param_pollution", "value": "&count=9999"},
            {"type": "param_pollution", "value": "&per_page=9999"},
            {"type": "param_pollution", "value": "&max=9999"},
            {"type": "param_pollution", "value": "&max_results=9999"},
            {"type": "param_pollution", "value": "&maxItems=9999"},
            {"type": "param_pollution", "value": "&maxRecords=9999"},
            # Header manipulation
            {"type": "header_manipulation", "value": "X-Limit-Bypass: true"},
            {"type": "header_manipulation", "value": "X-No-Rate-Limit: true"},
            {"type": "header_manipulation", "value": "X-Bypass-Rate-Limit: true"},
            {"type": "header_manipulation", "value": "X-RateLimit-Bypass: true"},
            {"type": "header_manipulation", "value": "X-RateLimit-Override: true"},
            {"type": "header_manipulation", "value": "X-Request-Limit: 9999"},
            {"type": "header_manipulation", "value": "X-RateLimit-Limit: 9999"},
            {"type": "header_manipulation", "value": "X-RateLimit-Reset: 0"},
            {"type": "header_manipulation", "value": "X-RateLimit-Remaining: 9999"},
            # Delay bypass
            {"type": "delay_bypass", "value": "sleep=0"},
            {"type": "delay_bypass", "value": "delay=0"},
            {"type": "delay_bypass", "value": "wait=0"},
            {"type": "delay_bypass", "value": "timeout=0"},
            # Referer manipulation
            {"type": "referer_manipulation", "value": "Referer: https://google.com"},
            {"type": "referer_manipulation", "value": "Referer: https://bing.com"},
            {"type": "referer_manipulation", "value": "Referer: https://yahoo.com"},
            {"type": "referer_manipulation", "value": "Referer: https://duckduckgo.com"}
        ]

        # Status codes that indicate rate limiting
        self.rate_limit_codes = [429, 503, 403, 401, 400]

        # Success indicators for bypass detection
        self.success_indicators = [
            "data", "success", "ok", "true", "200", "result",
            "response", "status", "code", "message", "content"
        ]

    def test_rate_limit(self) -> Dict:
        """Main rate limit detection"""
        log_info(f"Testing rate limit on {self.target}")

        results = {
            "rate_limit_detected": False,
            "threshold": None,
            "time_window": None,
            "reset_time": None,
            "max_requests": 0,
            "bypasses": [],
            "headers": {},
            "status_codes": []
        }

        # Send progressive requests
        request_count = 0
        status_codes = []
        header_checks = {}

        # First, get baseline response
        resp = self.client.get(self.target)
        if not resp:
            log_error("Failed to fetch target")
            return results

        # Check headers for rate limit information
        for header in self.rate_limit_headers:
            if header in resp.headers:
                value = resp.headers[header]
                header_checks[header] = value
                log_success(f"Rate limit header found: {header}: {value}")

                if 'limit' in header.lower() and value.isdigit():
                    results['threshold'] = int(value)
                    results['rate_limit_detected'] = True

                if 'remaining' in header.lower() and value.isdigit():
                    results['max_requests'] = int(value)

                if 'reset' in header.lower():
                    results['reset_time'] = value

        # Test with increasing request rates
        for i in range(1, 15):
            # Add slight delay to simulate real user
            time.sleep(0.1)

            # Send request
            resp = self.client.get(self.target)
            if not resp:
                break

            status_codes.append(resp.status_code)
            request_count += 1

            # Check if rate limited
            if resp.status_code in self.rate_limit_codes:
                # Check if Retry-After header exists
                retry_after = resp.headers.get('Retry-After', '')
                if retry_after:
                    results['time_window'] = retry_after
                    log_success(f"Rate limit detected! Status: {resp.status_code}, Retry-After: {retry_after}")
                else:
                    log_success(f"Rate limit detected! Status: {resp.status_code} at request {request_count}")

                results['rate_limit_detected'] = True
                results['threshold'] = request_count
                break

            if self.verbose and i % 5 == 0:
                log_debug(f"Request {i}: {resp.status_code}")

        results['status_codes'] = status_codes
        results['headers'] = header_checks
        results['request_count'] = request_count

        self.rate_limit_detected = results['rate_limit_detected']
        self.limit_threshold = results['threshold'] or 0
        self.time_window = results['time_window'] or 0

        return results

    def test_bypass_techniques(self) -> List[Dict]:
        """Test various rate limit bypass techniques"""
        log_info(f"Testing bypass techniques on {self.target}")
        bypasses = []

        for payload in self.bypass_payloads:
            bypass_type = payload['type']
            bypass_value = payload['value']

            if self.verbose:
                log_debug(f"Testing bypass: {bypass_type} - {bypass_value}")

            # Parse header
            try:
                if ': ' in bypass_value:
                    header_name, header_value = bypass_value.split(': ', 1)
                    headers = {header_name: header_value}
                    resp = self.client.get(self.target, headers=headers)
                else:
                    # Parameter pollution (add to URL)
                    if self.target.endswith('/'):
                        target_url = f"{self.target}?{bypass_value}"
                    elif '?' in self.target:
                        target_url = f"{self.target}&{bypass_value}"
                    else:
                        target_url = f"{self.target}?{bypass_value}"
                    resp = self.client.get(target_url)

                if resp and resp.status_code not in self.rate_limit_codes:
                    bypasses.append({
                        "type": bypass_type,
                        "value": bypass_value,
                        "status": resp.status_code,
                        "success": True,
                        "response_preview": resp.text[:100] if resp.text else ""
                    })
                    log_success(f"Bypass technique successful: {bypass_type} - {bypass_value}")

                elif self.verbose:
                    log_debug(f"Bypass failed: {bypass_type} - {bypass_value} -> {resp.status_code if resp else 'N/A'}")

            except Exception as e:
                if self.verbose:
                    log_debug(f"Bypass test error for {bypass_value}: {e}")

        return bypasses

    def run(self) -> Dict:
        log_info(f"Starting Rate Limit Check on: {self.target}")

        # Test rate limit
        rate_limit_results = self.test_rate_limit()

        # Test bypass techniques
        bypass_results = self.test_bypass_techniques()

        # Combine results
        final_results = {
            "target": self.target,
            "scan_type": "rate_limit",
            "rate_limit_detected": rate_limit_results.get('rate_limit_detected', False),
            "threshold": rate_limit_results.get('threshold', 0),
            "time_window": rate_limit_results.get('time_window', 0),
            "max_requests": rate_limit_results.get('max_requests', 0),
            "headers": rate_limit_results.get('headers', {}),
            "bypasses": bypass_results,
            "vulnerable": len(bypass_results) > 0
        }

        if final_results['vulnerable']:
            log_success(f"Rate limit can be bypassed! Found {len(bypass_results)} bypass techniques.")
        elif final_results['rate_limit_detected']:
            log_success("Rate limit detected but no bypass found.")
        else:
            log_warning("No rate limit detected.")

        return final_results
