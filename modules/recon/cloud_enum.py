#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class CloudEnum:
    def __init__(self, target, threads=20, verbose=False):
        self.target = target.lower()
        self.threads = threads
        self.verbose = verbose
        self.found = []
        self.lock = threading.Lock()

        # AWS S3 bucket patterns
        self.s3_patterns = [
            f"{self.target}",
            f"{self.target}-backup",
            f"{self.target}-data",
            f"{self.target}-assets",
            f"{self.target}-media",
            f"{self.target}-public",
            f"{self.target}-private",
            f"media-{self.target}",
            f"assets-{self.target}",
            f"data-{self.target}",
            f"backup-{self.target}",
            f"{self.target}-test",
            f"{self.target}-dev",
            f"{self.target}-prod",
            f"{self.target}-cdn"
        ]

        # Azure Blob patterns
        self.azure_patterns = [
            f"{self.target}.blob.core.windows.net",
            f"{self.target}data.blob.core.windows.net",
            f"{self.target}backup.blob.core.windows.net",
            f"{self.target}assets.blob.core.windows.net"
        ]

        # GCP Storage patterns
        self.gcp_patterns = [
            f"{self.target}.storage.googleapis.com",
            f"{self.target}-data.storage.googleapis.com",
            f"{self.target}-backup.storage.googleapis.com"
        ]

    def check_s3_bucket(self, bucket):
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                with self.lock:
                    self.found.append({
                        "type": "AWS S3",
                        "bucket": bucket,
                        "url": url,
                        "status": "public"
                    })
                    log_success(f"🔥 Found public S3 bucket: {bucket}")
            elif resp.status_code == 403:
                log_debug(f"S3 bucket {bucket} exists but is private")
        except:
            pass

    def check_azure_blob(self, url):
        try:
            resp = requests.get(f"https://{url}", timeout=5, allow_redirects=False)
            if resp.status_code == 200 or resp.status_code == 404:
                if "blob" in resp.headers.get("server", "").lower():
                    with self.lock:
                        self.found.append({
                            "type": "Azure Blob",
                            "url": f"https://{url}",
                            "status": "exists"
                        })
                        log_success(f"🔥 Found Azure Blob: {url}")
        except:
            pass

    def check_gcp_storage(self, url):
        try:
            resp = requests.get(f"https://{url}", timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                with self.lock:
                    self.found.append({
                        "type": "GCP Storage",
                        "url": f"https://{url}",
                        "status": "public"
                    })
                    log_success(f"🔥 Found GCP Storage: {url}")
        except:
            pass

    def run(self):
        log_info(f"Starting Cloud Enumeration on: {self.target}")
        log_info(f"Checking {len(self.s3_patterns)} S3 buckets...")
        log_info(f"Checking {len(self.azure_patterns)} Azure blobs...")
        log_info(f"Checking {len(self.gcp_patterns)} GCP buckets...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Check S3
            for bucket in self.s3_patterns:
                executor.submit(self.check_s3_bucket, bucket)
            
            # Check Azure
            for azure in self.azure_patterns:
                executor.submit(self.check_azure_blob, azure)
            
            # Check GCP
            for gcp in self.gcp_patterns:
                executor.submit(self.check_gcp_storage, gcp)

        log_success(f"Cloud enumeration completed. Found {len(self.found)} cloud resources.")
        return {
            "target": self.target,
            "scan_type": "cloud_enum",
            "total_found": len(self.found),
            "resources": self.found
        }
