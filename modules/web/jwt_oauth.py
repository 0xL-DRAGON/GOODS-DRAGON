#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import jwt
import re
import base64
import json
from core.logger import log_info, log_success, log_warning
from modules.core.http_client import HTTPClient

class JWTOAuthTester:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.results = []
        self.jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')

    def extract_tokens(self, text):
        """استخراج JWT از متن"""
        return self.jwt_pattern.findall(text)

    def decode_jwt(self, token):
        """دیکد کردن JWT بدون بررسی امضا"""
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            return header, payload
        except Exception as e:
            if self.verbose:
                log_warning(f"JWT decode error: {e}")
            return None, None

    def test_weak_secret(self, token):
        """ت测试 رمز ضعیف JWT"""
        weak_secrets = ['secret', 'password', '123456', 'admin', 'jwt', 'key']
        for secret in weak_secrets:
            try:
                decoded = jwt.decode(token, secret, algorithms=['HS256'])
                log_success(f"🔥 Weak JWT secret found: {secret}")
                return secret
            except:
                pass
        return None

    def check_oauth(self):
        """بررسی OAuth endpoints"""
        log_info("Checking OAuth endpoints...")
        endpoints = [
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/revoke",
            "/oauth2/authorize",
            "/oauth2/token",
            "/auth/authorize",
            "/auth/token",
            "/api/oauth/token",
            "/api/v1/oauth/token"
        ]
        found = []
        for endpoint in endpoints:
            url = f"{self.target}{endpoint}"
            resp = self.client.get(url)
            if resp and resp.status_code != 404:
                found.append({"url": url, "status": resp.status_code})
                log_success(f"Found OAuth endpoint: {url}")
        return found

    def run(self):
        log_info(f"Starting JWT & OAuth Testing on: {self.target}")
        
        # استخراج JWT از صفحه اصلی
        resp = self.client.get(self.target)
        if resp:
            tokens = self.extract_tokens(resp.text)
            for token in tokens:
                header, payload = self.decode_jwt(token)
                if header and payload:
                    secret = self.test_weak_secret(token)
                    self.results.append({
                        "token": token[:50] + "...",
                        "header": header,
                        "payload": payload,
                        "weak_secret": secret
                    })
                    log_success(f"Found JWT: {header.get('alg', 'unknown')}")

        # بررسی OAuth
        oauth = self.check_oauth()
        
        log_success(f"JWT/OAuth scan completed. Found {len(self.results)} tokens.")
        return {
            "target": self.target,
            "scan_type": "jwt_oauth",
            "tokens": self.results,
            "oauth_endpoints": oauth
        }
