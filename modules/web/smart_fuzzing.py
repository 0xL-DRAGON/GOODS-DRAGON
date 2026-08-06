#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import string
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class SmartFuzzing:
    def __init__(self, target, depth=100, verbose=False):
        self.target = target.rstrip("/")
        self.depth = depth
        self.verbose = verbose
        self.results = []

        # Base payloads for mutation
        self.base_payloads = [
            "'",
            '"',
            "`",
            "\\",
            "/",
            "..",
            ";",
            "|",
            "&",
            "$",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            "@",
            "#",
            "%",
            "!",
            "~",
            "=",
            "+",
            "*",
            "?",
            "^",
            "<",
            ">",
            "0x00",
            "0x01",
            "0x0a",
            "0x0d",
        ]

        # Fuzzing patterns
        self.patterns = [
            lambda: "".join(
                random.choices(string.ascii_lowercase, k=random.randint(1, 10))
            ),
            lambda: "".join(random.choices(string.digits, k=random.randint(1, 10))),
            lambda: "".join(
                random.choices(
                    string.ascii_letters + string.digits, k=random.randint(1, 10)
                )
            ),
            lambda: "".join(random.choices(string.printable, k=random.randint(1, 10))),
        ]

    def generate_payload(self):
        """Generate a random fuzzing payload"""
        payload_type = random.choice(["string", "number", "special", "mixed"])
        if payload_type == "string":
            return "".join(
                random.choices(string.ascii_letters, k=random.randint(1, 20))
            )
        elif payload_type == "number":
            return str(random.randint(0, 10 ** random.randint(1, 5)))
        elif payload_type == "special":
            return "".join(random.choices(self.base_payloads, k=random.randint(1, 5)))
        else:
            return "".join(
                random.choices(
                    string.ascii_letters + string.digits + "'\"\\/;",
                    k=random.randint(1, 15),
                )
            )

    def extract_params(self):
        parsed = urlparse(self.target)
        if not parsed.query:
            return {}
        return parse_qs(parsed.query)

    def build_url(self, params):
        parsed = urlparse(self.target)
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def fuzz_param(self, param, original_value):
        """Fuzz a single parameter"""
        for i in range(self.depth):
            payload = self.generate_payload()
            params = self.extract_params()
            if param in params:
                params[param] = [payload]
            else:
                params[param] = payload
            test_url = self.build_url(params)

            try:
                start_time = time.time()
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                elapsed = time.time() - start_time

                # Check for anomalies
                if resp.status_code in [500, 502, 503, 504]:
                    result = {
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "status": resp.status_code,
                        "type": "server_error",
                    }
                    self.results.append(result)
                    log_success(
                        f"🔥 Server error found on {param} with payload: {payload[:20]}... ({resp.status_code})"
                    )

                elif elapsed > 2.0:
                    result = {
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "time": elapsed,
                        "type": "timeout",
                    }
                    self.results.append(result)
                    log_success(
                        f"🔥 Timeout found on {param} with payload: {payload[:20]}... ({elapsed:.2f}s)"
                    )

                elif resp.status_code == 200 and len(resp.text) > 5000:
                    result = {
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "type": "large_response",
                    }
                    self.results.append(result)
                    log_success(
                        f"🔥 Large response found on {param} with payload: {payload[:20]}... ({len(resp.text)} bytes)"
                    )

                elif self.verbose and i % 10 == 0:
                    log_debug(
                        f"Fuzzed {param} with {payload[:20]}... -> {resp.status_code}"
                    )

            except requests.exceptions.Timeout:
                result = {
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "type": "timeout_exception",
                }
                self.results.append(result)
                log_success(
                    f"🔥 Timeout exception on {param} with payload: {payload[:20]}..."
                )
            except Exception as e:
                if self.verbose:
                    log_debug(f"Error fuzzing {param}: {e}")

    def run(self):
        log_info(f"Starting Smart Fuzzing on: {self.target}")
        log_info(f"Depth: {self.depth} payloads per parameter")

        params = self.extract_params()
        if not params:
            log_warning(
                "No GET parameters found. Fuzzing works best with parameters like ?id=1"
            )
            return {"target": self.target, "scan_type": "smart_fuzzing", "results": []}

        for param in params.keys():
            original_value = params[param][0] if params[param] else "1"
            log_info(f"Fuzzing parameter: {param} (original: {original_value})")
            self.fuzz_param(param, original_value)

        log_success(f"Smart Fuzzing completed. Found {len(self.results)} anomalies.")
        return {
            "target": self.target,
            "scan_type": "smart_fuzzing",
            "total_anomalies": len(self.results),
            "results": self.results,
        }
