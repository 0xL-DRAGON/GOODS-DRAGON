#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from core.logger import log_info, log_success, log_warning
from modules.core.http_client import HTTPClient


class APIKeyScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.keys = []

        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"[0-9a-zA-Z/+]{40}",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "GitHub Token": r"gh[ops]_[0-9a-zA-Z]{36}",
            "GitHub PAT": r"[0-9a-f]{40}",
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
            "API Key Generic": r"api[_-]?key[\s]*[:=][\s]*['\"]?[0-9a-zA-Z]{16,64}['\"]?",
            "Bearer Token": r"Bearer\s+[0-9a-zA-Z\-_.]+",
            "MongoDB URI": r"mongodb://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9]+\.mongodb\.net",
            "MySQL URI": r"mysql://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9]+\.(com|net|org)",
            "PostgreSQL URI": r"postgresql://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9]+\.(com|net|org)",
            "Redis URI": r"redis://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9]+\.(com|net|org)",
        }

    def scan_url(self, url):
        """Scan URL to find keys"""
        try:
            resp = self.client.get(url)
            if not resp:
                return
            content = resp.text
            for name, pattern in self.patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 8:
                        self.keys.append(
                            {
                                "type": name,
                                "value": (
                                    match[:20] + "..." if len(match) > 20 else match
                                ),
                                "full": match,
                                "source": url,
                            }
                        )
                        log_success(f"🔥 Found {name}: {match[:20]}...")
        except Exception as e:
            log_warning(f"Error scanning {url}: {e}")

    def run(self):
        log_info(f"Starting API Key Scanner on: {self.target}")

        # Scan main page
        self.scan_url(self.target)

        # Scan sensitive files
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
            "/secrets.yml",
            "/credentials.json",
            "/service-account.json",
            "/.aws/credentials",
            "/.aws/config",
            "/composer.json",
            "/package.json",
            "/.htaccess",
            "/.htpasswd",
        ]

        for path in sensitive_paths:
            url = f"{self.target}{path}"
            self.scan_url(url)

        log_success(f"API Key Scan completed. Found {len(self.keys)} keys.")
        return {
            "target": self.target,
            "scan_type": "api_key_scanner",
            "total_found": len(self.keys),
            "keys": self.keys,
        }
