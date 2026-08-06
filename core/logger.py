#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os
from datetime import datetime
from core.color_config import use_colors

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"

LOG_FILE = "logs/activity.log"

def ensure_log_dir():
    os.makedirs("logs", exist_ok=True)

def write_log(msg, level="INFO"):
    ensure_log_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [{level}] {msg}\n")

def _color(color, msg):
    """Apply color if enabled."""
    if use_colors():
        return f"{color}{msg}{RESET}"
    return msg

def log_info(msg):
    print(_color(BLUE, f"[*] {msg}"))
    write_log(msg, "INFO")

def log_success(msg):
    print(_color(GREEN, f"[+] {msg}"))
    write_log(msg, "SUCCESS")

def log_warning(msg):
    print(_color(YELLOW, f"[!] {msg}"))
    write_log(msg, "WARNING")

def log_error(msg):
    print(_color(RED, f"[-] {msg}"))
    write_log(msg, "ERROR")

def log_debug(msg):
    print(_color(PURPLE, f"[DEBUG] {msg}"))
    write_log(msg, "DEBUG")

def log_raw(msg):
    print(msg)
    write_log(msg, "RAW")
