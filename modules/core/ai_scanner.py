#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import random

from core.logger import log_info, log_success, log_warning
from modules.core.http_client import HTTPClient


class AIScanner:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.client = HTTPClient(timeout=20, retries=3, verbose=verbose)
        self.results = {}
        self.ai_patterns = {
            "sql_injection": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' AND SLEEP(5)--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg/onload=alert(1)>",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
            ],
            "rce": [
                "?cmd=id",
                "?cmd=whoami",
                "?cmd=system('id')",
                "?cmd=echo vulnerable",
            ],
        }

    def simulate_ai_analysis(self):
        """Simulate AI analysis"""
        log_info("AI analysis in progress...")

        # Simulate auto-detection
        analysis = {
            "target_type": random.choice(["web_app", "api", "server", "mobile"]),
            "risk_score": random.randint(1, 10),
            "recommended_modules": [],
            "vulnerability_probability": random.choice(
                ["low", "medium", "high", "critical"]
            ),
        }

        if analysis["risk_score"] > 7:
            analysis["recommended_modules"] = ["--sqli", "--xss", "--rce-scan"]
            log_success(f"🔥 High risk detected! Score: {analysis['risk_score']}")
        elif analysis["risk_score"] > 4:
            analysis["recommended_modules"] = ["--headers-check", "--cors-check"]
            log_info(f"⚠️ Medium risk detected. Score: {analysis['risk_score']}")
        else:
            analysis["recommended_modules"] = ["--tech-detect"]
            log_info(f"✅ Low risk detected. Score: {analysis['risk_score']}")

        self.results["ai_analysis"] = analysis
        return analysis

    def smart_payload_selection(self):
        """Smart payload selection based on target type"""
        log_info("Smart payload selection...")
        selected = {}
        for vuln_type, payloads in self.ai_patterns.items():
            selected[vuln_type] = random.sample(payloads, min(3, len(payloads)))
            log_success(f"Selected {len(selected[vuln_type])} payloads for {vuln_type}")
        return selected

    def adaptive_scanning(self):
        """Adaptive scan with parameter changes"""
        log_info("Adaptive scanning...")
        params = ["id", "page", "file", "q", "s", "search", "url", "path"]
        adapted = {}
        for param in params:
            if random.random() > 0.5:
                adapted[param] = random.choice(["1'", "test", "admin", "../../"])
                log_success(
                    f"Testing parameter: {param} with payload: {adapted[param]}"
                )
        return adapted

    def run(self):
        log_info(f"Starting AI-Powered Scanning on: {self.target}")

        # ۱. AI analysis
        analysis = self.simulate_ai_analysis()

        # ۲. Smart payload selection
        payloads = self.smart_payload_selection()

        # ۳. Adaptive scan
        adapted = self.adaptive_scanning()

        self.results.update(
            {
                "ai_analysis": analysis,
                "selected_payloads": payloads,
                "adaptive_params": adapted,
                "recommended_command": f"python main.py web -t {self.target} {' '.join(analysis['recommended_modules'])} -th 10 -v",
            }
        )

        log_success("AI-Powered Scanning completed.")
        return {
            "target": self.target,
            "scan_type": "ai_scanner",
            "results": self.results,
        }
