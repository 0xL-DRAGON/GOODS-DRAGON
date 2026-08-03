#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import log_info, log_success, log_debug, log_error

class PortScanner:
    def __init__(self, target, ports="21,22,23,25,80,443,3306,3389,8080", threads=50, verbose=False, banner=False):
        self.target = target
        self.threads = threads
        self.verbose = verbose
        self.grab_banner = banner
        self.open_ports = []
        self.lock = threading.Lock()

        # Parse ports
        if '-' in ports:
            start, end = ports.split('-')
            self.port_list = list(range(int(start), int(end) + 1))
        else:
            self.port_list = [int(p.strip()) for p in ports.split(',')]

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((self.target, port))
            sock.close()

            if result == 0:
                service = self.get_service(port)
                banner_text = ""
                if self.grab_banner:
                    banner_text = self.grab_banner_info(port)
                with self.lock:
                    self.open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner_text
                    })
                    log_success(f"Port {port} open - {service} {banner_text}")
            elif self.verbose:
                log_debug(f"Port {port} closed")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error on port {port}: {e}")

    def get_service(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
        }
        return services.get(port, "Unknown")

    def grab_banner_info(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            if port == 80 or port == 8080:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass
            elif port == 22:
                pass
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip().split('\n')[0]
            sock.close()
            return banner[:100]
        except:
            return ""

    def run(self):
        log_info(f"Starting Port Scan on: {self.target}")
        log_info(f"Scanning {len(self.port_list)} ports with {self.threads} threads...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.port_list}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    log_error(f"Thread error: {e}")

        log_success(f"Scan completed. Found {len(self.open_ports)} open ports.")
        return {
            "target": self.target,
            "scan_type": "port_scan",
            "open_ports": self.open_ports
        }
