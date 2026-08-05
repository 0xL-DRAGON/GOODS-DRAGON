#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import time
import requests
import threading
from core.logger import log_info, log_success, log_warning, log_error

class ProxyManager:
    def __init__(self, verbose=False, auto_rotate=True, rotate_interval=30):
        self.proxies = []
        self.verbose = verbose
        self.auto_rotate = auto_rotate
        self.rotate_interval = rotate_interval
        self.current_proxy_index = 0
        self.lock = threading.Lock()
        self._stop_rotation = False
        self._rotation_thread = None

    def fetch_free_proxies(self):
        """دریافت پروکسی‌های رایگان از APIهای عمومی (با منابع جایگزین و قابل‌دسترس)"""
        log_info("Fetching free proxies from public APIs...")
        
        # منابع جایگزین (قابل‌دسترس در ایران)
        proxy_sources = [
            # GitHub منابع (معمولاً در دسترس هستند)
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            # Geonode (معمولاً در دسترس است)
            "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc",
            "https://proxylist.geonode.com/api/proxy-list?limit=100&page=2&sort_by=lastChecked&sort_type=desc"
        ]
        
        all_proxies = []
        for url in proxy_sources:
            try:
                # افزایش timeout برای GitHub
                timeout = 30 if 'github' in url else 15
                resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
                
                if resp.status_code == 200:
                    if 'geonode' in url:
                        # پردازش JSON برای Geonode
                        try:
                            data = resp.json()
                            for item in data.get('data', []):
                                if item.get('protocols') and item.get('ip') and item.get('port'):
                                    protocol = item['protocols'][0].lower()
                                    if protocol in ['http', 'https']:
                                        all_proxies.append(f"http://{item['ip']}:{item['port']}")
                                    elif protocol in ['socks4', 'socks5']:
                                        all_proxies.append(f"{protocol}://{item['ip']}:{item['port']}")
                        except:
                            pass
                    else:
                        # پردازش لیست ساده
                        proxies = resp.text.strip().split('\n')
                        proxies = [p.strip() for p in proxies if p.strip() and not p.startswith('#')]
                        all_proxies.extend(proxies)
                    
                    if self.verbose:
                        log_success(f"Fetched proxies from {url.split('/')[2]}")
                else:
                    if self.verbose:
                        log_warning(f"Failed from {url.split('/')[2]} (Status: {resp.status_code})")
            except Exception as e:
                if self.verbose:
                    log_warning(f"Failed from {url.split('/')[2]}: {e}")
        
        # حذف پروکسی‌های تکراری و فرمت‌دهی
        cleaned_proxies = []
        for p in all_proxies:
            p = p.strip()
            if p and ':' in p and len(p) > 5:
                # اگر پروکسی بدون پروتکل بود، http:// اضافه کن
                if not p.startswith('http://') and not p.startswith('socks'):
                    p = f"http://{p}"
                cleaned_proxies.append(p)
        
        cleaned_proxies = list(set(cleaned_proxies))
        
        if cleaned_proxies:
            log_success(f"Total unique proxies fetched: {len(cleaned_proxies)}")
            self.proxies = cleaned_proxies
            return True
        else:
            log_warning("No proxies fetched. Using fallback list.")
            self.proxies = self._fallback_proxies()
            return False

    def _fallback_proxies(self):
        """لیست پروکسی‌های ثابت (در صورت عدم دسترسی به API)"""
        # این لیست رو می‌تونی با پروکسی‌های معتبر خودت جایگزین کنی
        return [
            "http://51.75.126.130:3128",
            "http://51.75.126.130:8080",
            "http://51.75.126.130:80",
            "http://51.75.126.130:443",
            "http://51.75.126.130:1080",
            "http://51.75.126.130:8888"
        ]

    def test_proxy(self, proxy):
        """بررسی صحت یک پروکسی"""
        try:
            test_url = "http://httpbin.org/ip"
            resp = requests.get(test_url, proxies={"http": proxy, "https": proxy}, timeout=5)
            return resp.status_code == 200
        except:
            return False

    def get_proxy(self):
        """دریافت یک پروکسی معتبر"""
        with self.lock:
            if not self.proxies:
                log_warning("No proxies available. Fetching new list...")
                self.fetch_free_proxies()
            
            if not self.proxies:
                log_warning("No proxies available. Using direct connection.")
                return None
            
            # چرخش پروکسی
            if self.auto_rotate:
                proxy = self.proxies[self.current_proxy_index % len(self.proxies)]
                self.current_proxy_index += 1
                return proxy
            else:
                return random.choice(self.proxies)

    def remove_dead_proxy(self, proxy):
        """حذف پروکسی مرده از لیست"""
        with self.lock:
            if proxy in self.proxies:
                self.proxies.remove(proxy)
                log_warning(f"Removed dead proxy: {proxy}")

    def _rotate_loop(self):
        """حلقه چرخش خودکار پروکسی"""
        while not self._stop_rotation:
            time.sleep(self.rotate_interval)
            if self.proxies:
                current = self.proxies[self.current_proxy_index % len(self.proxies)]
                log_info(f"🔄 Rotating proxy to: {current}")
                self.current_proxy_index += 1

    def start_rotation(self):
        """شروع چرخش خودکار پروکسی"""
        if self.auto_rotate and not self._rotation_thread:
            self._stop_rotation = False
            self._rotation_thread = threading.Thread(target=self._rotate_loop, daemon=True)
            self._rotation_thread.start()
            log_success("Automatic proxy rotation started.")

    def stop_rotation(self):
        """توقف چرخش خودکار پروکسی"""
        self._stop_rotation = True
        if self._rotation_thread:
            self._rotation_thread.join(timeout=2)
            self._rotation_thread = None
            log_info("Automatic proxy rotation stopped.")

    def run(self):
        """اجرای کامل مدیریت پروکسی"""
        log_info("=== Starting Proxy Manager ===")
        self.fetch_free_proxies()
        self.start_rotation()
        return {
            "status": "ready",
            "total_proxies": len(self.proxies),
            "auto_rotate": self.auto_rotate,
            "rotate_interval": self.rotate_interval
        }
