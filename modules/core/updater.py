#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import subprocess
import sys

import requests

from core.logger import log_error, log_info, log_success, log_warning


class SelfUpdater:
    def __init__(
        self, repo_owner="0xL-DRAGON", repo_name="GOODS-DRAGON", current_version="1.1.0"
    ):
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.current_version = current_version
        self.api_url = (
            f"https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest"
        )

    def check_for_updates(self):
        """بررسی وجود نسخه جدید در گیت‌هاب"""
        log_info("Checking for updates...")
        try:
            resp = requests.get(self.api_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                latest_version = data.get("tag_name", "").replace("v", "")
                if latest_version > self.current_version:
                    log_success(f"New version available: v{latest_version}")
                    return latest_version, data.get("assets", [])
                else:
                    log_info("You are using the latest version.")
                    return None, []
            else:
                log_error(f"Failed to check updates: {resp.status_code}")
                return None, []
        except Exception as e:
            log_error(f"Error checking updates: {e}")
            return None, []

    def download_update(self, assets):
        """دانلود فایل اصلی از ریلیز"""
        for asset in assets:
            if asset.get("name") == "main.py":
                url = asset.get("browser_download_url")
                if url:
                    log_info(f"Downloading update from {url}...")
                    try:
                        resp = requests.get(url, timeout=30)
                        if resp.status_code == 200:
                            with open("main.py.new", "wb") as f:
                                f.write(resp.content)
                            log_success("Update downloaded successfully.")
                            return True
                    except Exception as e:
                        log_error(f"Download failed: {e}")
        return False

    def apply_update(self):
        """اعمال به‌روزرسانی"""
        if os.path.exists("main.py.new"):
            log_info("Applying update...")
            try:
                # پشتیبان‌گیری از فایل فعلی
                os.rename("main.py", "main.py.bak")
                os.rename("main.py.new", "main.py")
                os.chmod("main.py", 0o755)
                log_success("Update applied successfully!")
                log_info("Please restart the tool.")
                return True
            except Exception as e:
                log_error(f"Failed to apply update: {e}")
                # برگرداندن به حالت قبل
                if os.path.exists("main.py.bak"):
                    os.rename("main.py.bak", "main.py")
        return False

    def run(self):
        """اجرای کامل فرآیند به‌روزرسانی"""
        latest_version, assets = self.check_for_updates()
        if latest_version and assets:
            if self.download_update(assets):
                self.apply_update()
                return True
        return False
