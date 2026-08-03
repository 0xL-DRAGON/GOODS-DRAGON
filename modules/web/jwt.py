#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import base64
import json
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class JWTScanner:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = []
        self.jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')

    def extract_jwt(self, text):
        return self.jwt_pattern.findall(text)

    def decode_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            return header, payload
        except Exception as e:
            if self.verbose:
                log_debug(f"Error decoding JWT: {e}")
            return None, None

    def check_jwt(self, token):
        header, payload = self.decode_jwt(token)
        if header and payload:
            result = {
                "token": token[:50] + "...",
                "header": header,
                "payload": payload,
                "algorithms": header.get('alg', 'unknown'),
                "exp": payload.get('exp', 'none'),
                "user": payload.get('sub', payload.get('user', payload.get('username', 'unknown')))
            }
            self.results.append(result)
            log_success(f"🔥 JWT found: {header.get('alg', 'unknown')} - {payload.get('sub', 'unknown')}")
            return result
        return None

    def run(self):
        log_info(f"Starting JWT scan on: {self.target}")
        try:
            import requests
            resp = requests.get(self.target, timeout=10, allow_redirects=False)
            tokens = self.extract_jwt(resp.text)
            for cookie in resp.cookies:
                tokens.extend(self.extract_jwt(cookie.value))
            
            if tokens:
                log_info(f"Found {len(tokens)} JWT tokens")
                for token in tokens:
                    self.check_jwt(token)
            else:
                log_info("No JWT tokens found")
        except Exception as e:
            log_error(f"Error: {e}")
        
        log_success(f"JWT scan completed. Found {len(self.results)} tokens.")
        return {"target": self.target, "scan_type": "jwt", "total": len(self.results), "tokens": self.results}
