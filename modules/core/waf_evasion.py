#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import time
import urllib.parse

from core.logger import log_info, log_success


class WAFEvasion:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.techniques = [
            self._case_swapping,
            self._url_encoding,
            self._double_encoding,
            self._comment_insertion,
            self._whitespace_insertion,
            self._parameter_pollution,
            self._null_byte_injection,
        ]

    def _case_swapping(self, payload):
        """Change case (مثلاً SeLeCt)"""
        return "".join(random.choice([c.upper(), c.lower()]) for c in payload)

    def _url_encoding(self, payload):
        """URL encode"""
        return urllib.parse.quote(payload)

    def _double_encoding(self, payload):
        """کدگذاری دوبل URL"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _comment_insertion(self, payload):
        """اضافه کردن کامنت‌های SQL"""
        if "'" in payload or '"' in payload:
            return payload.replace("'", "'/**/")
        return payload + "/**/"

    def _whitespace_insertion(self, payload):
        """Add spaces‌های تصادفی"""
        chars = list(payload)
        for i in range(len(chars)):
            if random.random() < 0.2:
                chars.insert(i, random.choice([" ", "\t", "\n"]))
        return "".join(chars)

    def _parameter_pollution(self, payload):
        """Inject parameterهای تکراری"""
        return f"{payload}&id={random.randint(1,999)}"

    def _null_byte_injection(self, payload):
        """تزریق Null Byte"""
        return payload + "%00"

    def apply_all(self, payload):
        """اعمال همه تکنیک‌ها به صورت تصادفی"""
        modified = payload
        for technique in random.sample(self.techniques, random.randint(1, 3)):
            try:
                modified = technique(modified)
            except:
                pass
        return modified

    def run(self):
        log_info("=== WAF Evasion Advanced ===")
        log_success("WAF Evasion techniques ready.")
        return {
            "status": "ready",
            "techniques": [t.__name__.replace("_", " ") for t in self.techniques],
        }
