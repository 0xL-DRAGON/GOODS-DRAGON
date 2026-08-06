#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class TwoFABypass:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.results = []

    def check_2fa(self):
        try:
            resp = requests.get(self.target, timeout=10, allow_redirects=False)
            html = resp.text

            # Check for common 2FA indicators
            indicators = [
                "2fa",
                "two-factor",
                "authenticator",
                "totp",
                "mfa",
                "verification code",
                "security code",
                "otp",
                "two step",
                "2-step",
                "google authenticator",
            ]

            found = []
            for ind in indicators:
                if ind in html.lower():
                    found.append(ind)

            if found:
                self.results.append(
                    {
                        "url": self.target,
                        "2fa_detected": True,
                        "indicators": found,
                        "status": "2FA present",
                    }
                )
                log_success(f"🔥 2FA detected on {self.target}")
            else:
                self.results.append(
                    {
                        "url": self.target,
                        "2fa_detected": False,
                        "message": "No 2FA indicators found",
                    }
                )
                log_info("No 2FA detected")
        except Exception as e:
            log_error(f"Error checking 2FA: {e}")

    def run(self):
        log_info(f"Starting 2FA Bypass check on: {self.target}")
        self.check_2fa()
        log_success(f"2FA check completed.")
        return {
            "target": self.target,
            "scan_type": "2fa_bypass",
            "results": self.results,
        }
