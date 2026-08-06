#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import log_debug, log_error, log_info, log_success


class HostDiscovery:
    def __init__(self, subnet, threads=50, verbose=False):
        self.subnet = subnet
        self.threads = threads
        self.verbose = verbose
        self.alive_hosts = []
        self.lock = threading.Lock()

    def ping_host(self, ip):
        """Check if host is alive using ICMP ping"""
        try:
            # Using system ping command (works on Linux/Termux)
            cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
            result = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
            )
            if result.returncode == 0:
                with self.lock:
                    self.alive_hosts.append(str(ip))
                    log_success(f"Host {ip} is alive")
                return True
            elif self.verbose:
                log_debug(f"Host {ip} is down")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error pinging {ip}: {e}")
        return False

    def tcp_check(self, ip, ports=[80, 443, 22]):
        """Fallback: check if TCP ports are open (if ping fails)"""
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    with self.lock:
                        if str(ip) not in self.alive_hosts:
                            self.alive_hosts.append(str(ip))
                            log_success(f"Host {ip} is alive (TCP port {port} open)")
                    return True
            except:
                pass
        return False

    def run(self):
        log_info(f"Starting Host Discovery on subnet: {self.subnet}")
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
            hosts = list(network.hosts())
            log_info(f"Scanning {len(hosts)} IP addresses...")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.ping_host, ip): ip for ip in hosts}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        if not future.result():
                            # If ping fails, try TCP fallback
                            self.tcp_check(ip)
                    except Exception as e:
                        log_error(f"Error scanning {ip}: {e}")

            log_success(
                f"Host discovery completed. Found {len(self.alive_hosts)} alive hosts."
            )
            return {
                "target": self.subnet,
                "scan_type": "host_discovery",
                "total_alive": len(self.alive_hosts),
                "hosts": self.alive_hosts,
            }
        except Exception as e:
            log_error(f"Invalid subnet: {e}")
            return {"target": self.subnet, "error": str(e)}
