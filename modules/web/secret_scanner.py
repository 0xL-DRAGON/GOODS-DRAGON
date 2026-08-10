#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class SecretScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.secrets = []

        # Patterns for common secrets and API keys
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"[0-9a-zA-Z/+]{40}",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "GitHub Token": r"gh[ops]_[0-9a-zA-Z]{36}",
            "GitHub Personal Access": r"[0-9a-f]{40}",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "Slack Token": r"xox[bpays]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "PayPal Client ID": r"CLIENT-[0-9a-zA-Z]{32}",
            "Twilio API Key": r"SK[0-9a-f]{32}",
            "SendGrid API Key": r"SG\.[0-9a-zA-Z]{22}\.[0-9a-zA-Z]{43}",
            "Heroku API Key": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "Facebook Access Token": r"EA[0-9a-zA-Z]{50,100}",
            "Instagram Access Token": r"IG[0-9a-zA-Z]{50,100}",
            "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "API Key Generic": r'api[_-]?key["\']?\s*[:=]\s*["\']?[0-9a-zA-Z]{16,64}["\']?',
            "Password": r'password["\']?\s*[:=]\s*["\']?[^"\']{4,32}["\']?',
            "Secret": r'secret["\']?\s*[:=]\s*["\']?[0-9a-zA-Z]{16,64}["\']?',
            "Bearer Token": r"Bearer\s+[0-9a-zA-Z\-_.]+",
            "Basic Auth": r"Basic\s+[0-9a-zA-Z+/=]+",
            "MongoDB URI": r"mongodb://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9]+\.mongodb\.net",
            "MySQL Connection": r"mysql://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9]+\.(com|net|org)",
            "PostgreSQL Connection": r"postgresql://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9]+\.(com|net|org)",
            "Redis Connection": r"redis://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9]+\.(com|net|org)",
        }

    def fetch_content(self, url):
        """Fetch content from URL"""
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False)
            if resp.status_code == 200:
                return resp.text
            elif self.verbose:
                log_debug(f"Status {resp.status_code} for {url}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error fetching {url}: {e}")
        return None

        def _is_false_positive(self, match):
        """Filter out known false positives."""
        # SVG path data
        if match.startswith("PHN2Zy") or "fill-rule" in match.lower():
            return True
        # Base64 encoded images
        if len(match) > 100 and match.count("/") > 5:
            return True
        # Smart contract addresses (blockchain)
        if match.startswith("0x") and len(match) == 42:
            return True
        # Currency/token names
        if match in ["Basic Attention", "Basic"]:
            return True
        return False
    
    def scan_content(self, content, source):
        """Scan content for secrets"""
        for name, pattern in self.patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                    if self._is_false_positive(match):
                        continue
                # Filter out common false positives
                if len(match) < 8 or match == "password" or match == "secret":
                    continue
                result = {
                    "type": name,
                    "value": match[:20] + "..." if len(match) > 20 else match,
                    "source": source,
                    "full_value": match,
                }
                self.secrets.append(result)
                log_success(f"🔥 Found {name}: {match[:20]}...")

    def scan(self):
        """Scan target for secrets"""
        log_info(f"Scanning {self.target} for secrets and API keys...")

        # Fetch main page
        content = self.fetch_content(self.target)
        if content:
            self.scan_content(content, self.target)

        # Scan common sensitive files
        sensitive_paths = [
            "/.env",
            "/.env.local",
            "/.env.backup",
            "/.git/config",
            "/.git/HEAD",
            "/config.php",
            "/wp-config.php",
            "/settings.py",
            "/config.yml",
            "/config.yaml",
            "/secrets.yml",
            "/secrets.yaml",
            "/credentials.json",
            "/service-account.json",
            "/.aws/credentials",
            "/.aws/config",
            "/.npmrc",
            "/.yarnrc",
            "/composer.json",
            "/package.json",
            "/.htaccess",
            "/.htpasswd",
        ]

        for path in sensitive_paths:
            url = f"{self.target}{path}"
            content = self.fetch_content(url)
            if content:
                self.scan_content(content, url)

    def run(self):
        log_info(f"Starting Secret Scanner on: {self.target}")
        self.scan()

        log_success(f"Secret scan completed. Found {len(self.secrets)} secrets.")
        return {
            "target": self.target,
            "scan_type": "secret_scanner",
            "total_found": len(self.secrets),
            "secrets": self.secrets,
        }
