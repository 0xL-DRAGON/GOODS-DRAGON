# -*- coding: utf-8 -*-
import sys
from datetime import datetime

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"

def log_info(msg):
    print(f"{BLUE}[*] {msg}{RESET}")

def log_success(msg):
    print(f"{GREEN}[+] {msg}{RESET}")

def log_warning(msg):
    print(f"{YELLOW}[!] {msg}{RESET}")

def log_error(msg):
    print(f"{RED}[-] {msg}{RESET}")

def log_debug(msg):
    print(f"{PURPLE}[DEBUG] {msg}{RESET}")
