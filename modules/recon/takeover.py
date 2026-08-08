#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import requests

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)


class SubdomainTakeover:
    def __init__(self, subdomains, verbose=False):
        self.subdomains = subdomains
        self.verbose = verbose
        self.vulnerable = []

        # Configure DNS resolver without /etc/resolv.conf
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

        # Known takeover signatures (CNAME + error patterns)
        self.signatures = {
            "github.io": {
                "cname": "github.io",
                "error": "There isn't a GitHub Pages site here.",
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
        }

    def check_takeover(self, subdomain):
        try:
            # Use custom resolver
            answers = self.resolver.resolve(subdomain, "CNAME")
            cname = str(answers[0].target).rstrip(".")

            # Check if CNAME matches any known vulnerable service
            for service, sig in self.signatures.items():
                if service in cname.lower():
                    # Check HTTP response for error pattern
                    try:
                        resp = requests.get(
                            f"http://{subdomain}", timeout=5, allow_redirects=False
                        )
                        if sig["error"].lower() in resp.text.lower():
                            result = {
                                "subdomain": subdomain,
                                "cname": cname,
                                "service": service,
                                "vulnerable": True,
                                "status": "takeover_possible",
                            }
                            self.vulnerable.append(result)
                            log_success(f"🔥 Possible takeover: {subdomain} -> {cname}")
                            return result
                    except:
                        pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            if self.verbose:
                log_debug(f"Error checking {subdomain}: {e}")
        return None

    def run(self):
        if not self.subdomains:
            log_warning("No subdomains provided to check for takeover.")
            return {
                "scan_type": "subdomain_takeover",
                "total_checked": 0,
                "vulnerable_count": 0,
                "vulnerable_subdomains": [],
            }

        log_info(
            f"Checking {len(self.subdomains)} subdomains for takeover vulnerabilities..."
        )
        for sub in self.subdomains:
            self.check_takeover(sub)

        if self.vulnerable:
            log_success(
                f"Found {len(self.vulnerable)} subdomains vulnerable to takeover."
            )
        else:
            log_info("No takeover vulnerabilities found.")
        return {
            "scan_type": "subdomain_takeover",
            "total_checked": len(self.subdomains),
            "vulnerable_count": len(self.vulnerable),
            "vulnerable_subdomains": self.vulnerable,
        }
