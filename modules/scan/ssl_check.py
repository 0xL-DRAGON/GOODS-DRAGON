#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ssl
import socket
import datetime
import re
from core.logger import log_info, log_success, log_debug, log_error, log_warning

class SSLChecker:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = []

    def check_ssl(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Get SSL/TLS version
                    protocol = ssock.version()
                    
                    # Extract certificate info
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    # Dates
                    not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.datetime.now()).days

                    self.results = {
                        "target": self.target,
                        "protocol": protocol,
                        "subject": subject.get('commonName', 'N/A'),
                        "issuer": issuer.get('organizationName', 'N/A'),
                        "not_before": not_before.strftime('%Y-%m-%d'),
                        "not_after": not_after.strftime('%Y-%m-%d'),
                        "days_left": days_left,
                        "valid": days_left > 0
                    }

                    log_success(f"SSL/TLS Check completed for {self.target}")
                    log_info(f"  Protocol: {protocol}")
                    log_info(f"  Subject: {subject.get('commonName', 'N/A')}")
                    log_info(f"  Issuer: {issuer.get('organizationName', 'N/A')}")
                    log_info(f"  Valid until: {not_after.strftime('%Y-%m-%d')} ({days_left} days left)")
                    
                    if days_left < 30:
                        log_warning(f"⚠️ Certificate expires in {days_left} days!")
                    elif days_left < 7:
                        log_error(f"❌ Certificate expires in {days_left} days!")
                    else:
                        log_success(f"✅ Certificate is valid for {days_left} days.")

        except socket.timeout:
            log_error(f"Connection timed out for {self.target}:443")
            self.results = {"target": self.target, "error": "Connection timeout"}
        except ConnectionRefusedError:
            log_error(f"Connection refused on {self.target}:443")
            self.results = {"target": self.target, "error": "Connection refused"}
        except ssl.SSLError as e:
            log_error(f"SSL Error: {e}")
            self.results = {"target": self.target, "error": str(e)}
        except Exception as e:
            log_error(f"Error: {e}")
            self.results = {"target": self.target, "error": str(e)}

        return self.results

    def run(self):
        log_info(f"Starting SSL/TLS Check on: {self.target}")
        result = self.check_ssl()
        return {
            "target": self.target,
            "scan_type": "ssl_check",
            "results": result
        }
