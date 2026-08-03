#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
from core.logger import log_info, log_success, log_error

class AutoScript:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.results = []

    def run_command(self, cmd):
        """Run a command and capture output"""
        log_info(f"Running: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if self.verbose:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return result.returncode == 0
        except Exception as e:
            log_error(f"Error running command: {e}")
            return False

    def run_recon(self):
        """Run all recon modules"""
        log_info("=== Starting Recon Phase ===")
        cmds = [
            f"python main.py recon -t {self.target} --active-scan --wayback --takeover --cloud-enum -v",
        ]
        for cmd in cmds:
            self.run_command(cmd)

    def run_web(self):
        """Run all web modules"""
        log_info("=== Starting Web Phase ===")
        cmds = [
            f"python main.py web -t {self.target} --sqli --xss --cms-detect --cve-scan --headers-check --js-deps --tech-detect --git-scan --waf-detect --idor-scan --ssti-scan --ssrf-scan --lfi-scan --cors-check --jwt-scan --open-redirect --graphql-scan --rate-limit --2fa-bypass --param-discovery --blind-xss --secret-scan --version-scan --broken-link --fuzz --business-logic --race-condition --chained-attack --static-analysis --report -v",
        ]
        for cmd in cmds:
            self.run_command(cmd)

    def run_network(self):
        """Run all network modules"""
        log_info("=== Starting Network Phase ===")
        cmds = [
            f"python main.py scan -t {self.target} --ssl-check -b -v",
        ]
        for cmd in cmds:
            self.run_command(cmd)

    def run_full(self):
        """Run full automation"""
        log_info("=== Starting Full Auto-Script ===")
        self.run_recon()
        self.run_web()
        self.run_network()
        log_success("Full automation completed!")

    def run(self):
        self.run_full()
