#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
from datetime import datetime

# رنگ‌های ترمینال
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"

# فایل لاگ
LOG_FILE = "logs/activity.log"

def ensure_log_dir():
    """ایجاد پوشه لاگ در صورت نیاز"""
    os.makedirs("logs", exist_ok=True)

def write_log(msg, level="INFO"):
    """نوشتن پیام در فایل لاگ"""
    ensure_log_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [{level}] {msg}\n")

def log_info(msg):
    """پیام اطلاعاتی آبی"""
    print(f"{BLUE}[*] {msg}{RESET}")
    write_log(msg, "INFO")

def log_success(msg):
    """پیام موفقیت سبز"""
    print(f"{GREEN}[+] {msg}{RESET}")
    write_log(msg, "SUCCESS")

def log_warning(msg):
    """پیام هشدار زرد"""
    print(f"{YELLOW}[!] {msg}{RESET}")
    write_log(msg, "WARNING")

def log_error(msg):
    """پیام خطا قرمز"""
    print(f"{RED}[-] {msg}{RESET}")
    write_log(msg, "ERROR")

def log_debug(msg):
    """پیام دیباگ بنفش"""
    print(f"{PURPLE}[DEBUG] {msg}{RESET}")
    write_log(msg, "DEBUG")

def log_raw(msg):
    """چاپ ساده بدون فرمت"""
    print(msg)
    write_log(msg, "RAW")
