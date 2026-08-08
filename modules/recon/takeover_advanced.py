#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import requests

from core.logger import log_info, log_success, log_warning
from modules.core.http_client import HTTPClient


class SubdomainTakeoverAdvanced:
    def __init__(self, domain, verbose=False):
        self.domain = domain
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.vulnerable = []

        # Takeover-able services with error signatures
        self.services = {
            "github.io": {
                "cname": "github.io",
                "error": "There isn't a GitHub Pages site here",
            },
            "herokuapp.com": {"cname": "herokuapp.com", "error": "No such app"},
            "s3.amazonaws.com": {"cname": "s3.amazonaws.com", "error": "NoSuchBucket"},
            "azurewebsites.net": {
                "cname": "azurewebsites.net",
                "error": "404 Web Site not found",
            },
            "cloudfront.net": {
                "cname": "cloudfront.net",
                "error": "The specified distribution does not exist",
            },
            "firebaseapp.com": {"cname": "firebaseapp.com", "error": "Site not found"},
            "netlify.com": {"cname": "netlify.com", "error": "Page not found"},
            "readthedocs.io": {
                "cname": "readthedocs.io",
                "error": "404 - Page Not Found",
            },
            "unbouncepages.com": {
                "cname": "unbouncepages.com",
                "error": "The requested URL was not found",
            },
            "fastly.net": {
                "cname": "fastly.net",
                "error": "Fastly error: unknown domain",
            },
            "shopify.com": {"cname": "shopify.com", "error": "Shopify"},
            "square.site": {
                "cname": "square.site",
                "error": "We couldn't find that page",
            },
        }

    def check_cname(self, subdomain):
        """Check CNAME of a subdomain"""
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME")
            cname = str(answers[0].target).rstrip(".")
            return cname
        except:
            return None

    def check_takeover(self, subdomain):
        """Check takeover possibility for a subdomain"""
        cname = self.check_cname(subdomain)
        if not cname:
            return

        for service, sig in self.services.items():
            if service in cname.lower():
                # HTTP check for takeover error
                try:
                    resp = self.client.get(f"http://{subdomain}")
                    if resp and sig["error"].lower() in resp.text.lower():
                        result = {
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": service,
                            "vulnerable": True,
                        }
                        self.vulnerable.append(result)
                        log_success(f"🔥 Takeover possible: {subdomain} -> {cname}")
                except:
                    pass

    def run(self):
        log_info(f"Starting Advanced Subdomain Takeover on: {self.domain}")

        # Common subdomain list
        common_subdomains = [
            "www",
            "mail",
            "ftp",
            "webmail",
            "smtp",
            "pop",
            "ns1",
            "cpanel",
            "admin",
            "blog",
            "dev",
            "vpn",
            "mysql",
            "api",
            "cdn",
            "git",
            "store",
            "help",
            "server",
            "test",
            "stage",
            "staging",
            "prod",
            "production",
            "backup",
            "assets",
            "media",
            "static",
            "images",
            "img",
            "video",
            "audio",
            "docs",
            "files",
            "uploads",
            "download",
            "app",
            "apps",
            "portal",
            "dashboard",
            "manage",
            "support",
            "docs",
            "wiki",
            "forum",
            "community",
            "status",
            "statuspage",
        ]

        for sub in common_subdomains:
            full_domain = f"{sub}.{self.domain}"
            self.check_takeover(full_domain)

        log_success(
            f"Takeover scan completed. Found {len(self.vulnerable)} vulnerable subdomains."
        )
        return {
            "target": self.domain,
            "scan_type": "takeover_advanced",
            "vulnerable": self.vulnerable,
        }
