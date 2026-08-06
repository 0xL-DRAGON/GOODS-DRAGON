#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import requests

from core.logger import log_error, log_info, log_success, log_warning


class CloudScanner:
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.results = []

    def check_s3_bucket(self, bucket):
        urls = [
            f"https://{bucket}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}",
        ]
        for url in urls:
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200 and "ListBucketResult" in resp.text:
                    log_success(f"Found open S3 bucket: {bucket}")
                    self.results.append(
                        {"type": "S3", "name": bucket, "url": url, "status": "public"}
                    )
                    return
                elif resp.status_code == 403:
                    log_info(f"Bucket {bucket} exists but is private")
                    self.results.append(
                        {"type": "S3", "name": bucket, "url": url, "status": "private"}
                    )
            except:
                pass

    def check_gcp_bucket(self, bucket):
        url = f"https://{bucket}.storage.googleapis.com"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                log_success(f"Found open GCP bucket: {bucket}")
                self.results.append(
                    {"type": "GCP", "name": bucket, "url": url, "status": "public"}
                )
            elif resp.status_code == 403:
                self.results.append(
                    {"type": "GCP", "name": bucket, "url": url, "status": "private"}
                )
        except:
            pass

    def check_azure_blob(self, blob):
        url = f"https://{blob}.blob.core.windows.net"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200 or resp.status_code == 404:
                log_success(f"Found Azure blob: {blob}")
                self.results.append(
                    {"type": "Azure", "name": blob, "url": url, "status": "exists"}
                )
        except:
            pass

    def scan_buckets(self):
        log_info(f"Scanning cloud resources for {self.domain}...")

        # S3 patterns
        patterns = [
            self.domain,
            f"{self.domain}-backup",
            f"{self.domain}-data",
            f"{self.domain}-assets",
            f"{self.domain}-media",
            f"cdn-{self.domain}",
            f"media-{self.domain}",
        ]

        for pattern in patterns:
            self.check_s3_bucket(pattern)
            self.check_gcp_bucket(pattern)
            self.check_azure_blob(pattern)

    def run(self):
        log_info(f"Starting Cloud Scanner on: {self.domain}")
        self.scan_buckets()
        log_success(f"Cloud scan completed. Found {len(self.results)} resources.")
        return {
            "target": self.domain,
            "scan_type": "cloud_scanner",
            "total_found": len(self.results),
            "resources": self.results,
        }
