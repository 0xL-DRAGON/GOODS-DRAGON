#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class ParameterDiscovery:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.found_params = []
        
        # Common parameter names to test
        self.common_params = [
            'id', 'user', 'page', 'cat', 'product', 'order', 'ref', 'doc', 'file', 'item',
            'q', 's', 'search', 'query', 'keyword', 'term', 'key',
            'url', 'link', 'path', 'dest', 'redirect', 'return', 'next',
            'name', 'email', 'phone', 'mobile', 'address', 'city', 'state', 'zip',
            'page_id', 'post_id', 'article_id', 'news_id', 'blog_id',
            'action', 'cmd', 'command', 'exec', 'run',
            'data', 'json', 'xml', 'api', 'v1', 'v2',
            'token', 'key', 'api_key', 'secret', 'auth',
            'debug', 'test', 'dev', 'stage', 'prod'
        ]

    def test_param(self, param, value="1"):
        """Test if a parameter is accepted by the server"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            resp = requests.get(test_url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                self.found_params.append({
                    "param": param,
                    "value": value,
                    "status": resp.status_code,
                    "content_length": len(resp.text)
                })
                log_success(f"✅ Found parameter: {param}")
                return True
            elif self.verbose:
                log_debug(f"Param {param} -> {resp.status_code}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error testing {param}: {e}")
        return False

    def run(self):
        log_info(f"Starting Parameter Discovery on: {self.target}")
        log_info(f"Testing {len(self.common_params)} common parameters...")
        
        for param in self.common_params:
            self.test_param(param)
        
        log_success(f"Found {len(self.found_params)} parameters.")
        return {
            "target": self.target,
            "scan_type": "param_discovery",
            "total_found": len(self.found_params),
            "parameters": self.found_params
        }
