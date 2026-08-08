#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

import dns.resolver

from core.logger import log_info, log_success
from modules.core.http_client import HTTPClient


class ADEnum:
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.results = {}

    def find_dc(self):
        """Find Domain Controller"""
        log_info(f"Finding Domain Controller for {self.domain}")
        try:
            answers = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{self.domain}", "SRV")
            for answer in answers:
                self.results["dc"] = str(answer.target).rstrip(".")
                log_success(f"Found DC: {self.results['dc']}")
                return
        except:
            pass
        self.results["dc"] = None

    def find_users(self):
        """Search users (Simulation)"""
        log_info(f"Searching users in {self.domain}")
        common_users = [
            "admin",
            "administrator",
            "root",
            "user",
            "test",
            "guest",
            "backup",
        ]
        self.results["users"] = common_users
        log_success(f"Found {len(common_users)} potential users")

    def find_shares(self):
        """Search shares (Simulation)"""
        log_info(f"Searching shares in {self.domain}")
        shares = ["C$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL"]
        self.results["shares"] = shares
        log_success(f"Found {len(shares)} default shares")

    def run(self):
        log_info(f"Starting AD Enumeration on: {self.domain}")
        self.find_dc()
        self.find_users()
        self.find_shares()
        log_success("AD Enumeration completed.")
        return {"target": self.domain, "scan_type": "ad_enum", "results": self.results}
