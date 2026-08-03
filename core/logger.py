# -*- coding: utf-8 -*-
import sys
from datetime import datetime

# کدهای رنگ برای ترمینال
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"

def log_info(msg):
    """پیام اطلاعاتی آبی"""
    print(f"{BLUE}[*] {msg}{RESET}")

def log_success(msg):
    """پیام موفقیت سبز"""
    print(f"{GREEN}[+] {msg}{RESET}")

def log_warning(msg):
    """پیام هشدار زرد"""
    print(f"{YELLOW}[!] {msg}{RESET}")

def log_error(msg):
    """پیام خطا قرمز"""
    print(f"{RED}[-] {msg}{RESET}")

def log_debug(msg):
    """پیام دیباگ بنفش (برای حالت verbose)"""
    print(f"{PURPLE}[DEBUG] {msg}{RESET}")
