#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GOODS-DRAGON - Automatic Dependency Checker & Installer
Ensures tool works independently without manual setup
"""

import importlib
import subprocess
import sys

from core.logger import log_error, log_info, log_success, log_warning

OPTIONAL_DEPENDENCIES = {
    "paramiko": {
        "package": "paramiko",
        "feature": "SSH/FTP/RDP Brute Force",
        "required_by": ["modules.scan.bruteforce"],
    },
    "selenium": {
        "package": "selenium",
        "feature": "Browser Emulator",
        "required_by": ["modules.core.browser_emulator"],
    },
    "cloudscraper": {
        "package": "cloudscraper",
        "feature": "Advanced Stealth Pro",
        "required_by": ["modules.core.stealth_pro"],
    },
}


def check_and_install(package_name, feature_name):
    """
    Check if a package is installed, offer to install if not.
    Returns True if available (either already or just installed).
    """
    try:
        importlib.import_module(package_name)
        return True
    except ImportError:
        log_warning(f"'{package_name}' is required for: {feature_name}")
        log_info(f"This feature needs an additional package to work.")

        response = input(f"[?] Install '{package_name}' now? (y/n): ").strip().lower()

        if response == "y":
            log_info(f"Installing {package_name}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                log_success(f"{package_name} installed successfully!")
                return True
            except subprocess.CalledProcessError:
                log_error(f"Failed to install {package_name}")
                log_info(f"Manual install: pip install {package_name}")
                return False
        else:
            log_info(f"Skipping {feature_name}")
            log_info(f"Install manually later: pip install {package_name}")
            return False


def check_module_dependencies(module_name):
    """
    Check and auto-install dependencies for a specific module.
    Returns True if dependency is available.
    """
    for pkg_name, info in OPTIONAL_DEPENDENCIES.items():
        if module_name in info["required_by"]:
            if not check_and_install(pkg_name, info["feature"]):
                return False
    return True


def print_dependency_status():
    """
    Show status of all optional dependencies.
    """
    log_info("=== Optional Dependencies Status ===")

    for pkg_name, info in OPTIONAL_DEPENDENCIES.items():
        try:
            importlib.import_module(pkg_name)
            log_success(f"✅ {pkg_name:15} - {info['feature']}")
        except ImportError:
            log_warning(f"❌ {pkg_name:15} - {info['feature']} (not installed)")

    log_info("Install missing ones with: pip install <package>")
