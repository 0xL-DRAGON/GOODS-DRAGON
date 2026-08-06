#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

import requests

from core.logger import log_error, log_info, log_success, log_warning


class PublicInfo:
    def __init__(self, target, verbose=False):
        self.target = target.strip()
        self.verbose = verbose
        self.results = {}

    def get_ip_info(self):
        """Get IP geolocation and ISP info"""
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{self.target}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    self.results["ip_info"] = {
                        "ip": data.get("query"),
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "organization": data.get("org"),
                        "as": data.get("as"),
                    }
                    log_success(f"IP Info retrieved for {self.target}")
                else:
                    log_warning(f"IP API error: {data.get('message')}")
            else:
                log_error(f"IP API returned status: {resp.status_code}")
        except Exception as e:
            log_error(f"Error fetching IP info: {e}")

    def get_country_info(self, country_code):
        """Get country details from restcountries API"""
        try:
            resp = requests.get(
                f"https://restcountries.com/v3.1/alpha/{country_code}", timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                if data and len(data) > 0:
                    country = data[0]
                    self.results["country_info"] = {
                        "name": country.get("name", {}).get("common", "N/A"),
                        "official_name": country.get("name", {}).get("official", "N/A"),
                        "capital": (
                            country.get("capital", ["N/A"])[0]
                            if country.get("capital")
                            else "N/A"
                        ),
                        "region": country.get("region", "N/A"),
                        "subregion": country.get("subregion", "N/A"),
                        "population": country.get("population", "N/A"),
                        "area": country.get("area", "N/A"),
                        "currency": (
                            list(country.get("currencies", {}).keys())[0]
                            if country.get("currencies")
                            else "N/A"
                        ),
                        "languages": (
                            ", ".join(country.get("languages", {}).values())
                            if country.get("languages")
                            else "N/A"
                        ),
                        "timezones": (
                            ", ".join(country.get("timezones", []))
                            if country.get("timezones")
                            else "N/A"
                        ),
                        "calling_code": country.get("idd", {}).get("root", "")
                        + (
                            country.get("idd", {}).get("suffixes", [""])[0]
                            if country.get("idd", {}).get("suffixes")
                            else ""
                        ),
                    }
                    log_success(f"Country info retrieved for {country_code}")
            else:
                log_error(f"Country API returned status: {resp.status_code}")
        except Exception as e:
            log_error(f"Error fetching country info: {e}")

    def get_domain_info(self):
        """Get domain WHOIS-like info (simplified)"""
        try:
            # Using free API for domain info (whois)
            resp = requests.get(
                f"https://api.vercel.com/v2/domains/{self.target}", timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                self.results["domain_info"] = {
                    "domain": self.target,
                    "name": data.get("name", "N/A"),
                    "verified": data.get("verified", False),
                    "created_at": data.get("createdAt", "N/A"),
                    "updated_at": data.get("updatedAt", "N/A"),
                }
                log_success(f"Domain info retrieved for {self.target}")
            else:
                # Fallback: try to get IP info only
                log_warning("Domain API unavailable, using IP info only")
        except:
            # If domain API fails, just use IP info
            log_warning("Domain info not available")

    def get_phone_prefix(self, country_code):
        """Get phone prefix for a country"""
        phone_prefixes = {
            "IR": "+98",
            "US": "+1",
            "GB": "+44",
            "DE": "+49",
            "FR": "+33",
            "IT": "+39",
            "ES": "+34",
            "PT": "+351",
            "NL": "+31",
            "BE": "+32",
            "CH": "+41",
            "AT": "+43",
            "SE": "+46",
            "NO": "+47",
            "DK": "+45",
            "FI": "+358",
            "IE": "+353",
            "NZ": "+64",
            "AU": "+61",
            "CA": "+1",
            "BR": "+55",
            "MX": "+52",
            "AR": "+54",
            "CL": "+56",
            "CO": "+57",
            "PE": "+51",
            "VE": "+58",
            "EG": "+20",
            "ZA": "+27",
            "NG": "+234",
            "KE": "+254",
            "TN": "+216",
            "MA": "+212",
            "DZ": "+213",
            "SA": "+966",
            "AE": "+971",
            "TR": "+90",
            "PK": "+92",
            "IN": "+91",
            "CN": "+86",
            "JP": "+81",
            "KR": "+82",
            "RU": "+7",
            "UA": "+380",
            "PL": "+48",
        }
        return phone_prefixes.get(country_code, "N/A")

    def run(self):
        log_info(f"Starting Public Info gathering for: {self.target}")

        # Check if target is IP or domain
        if self.target.replace(".", "").isdigit():
            # It's an IP
            self.get_ip_info()
            if self.results.get("ip_info"):
                country_code = self.results["ip_info"].get("country_code")
                if country_code:
                    self.get_country_info(country_code)
                    # Add phone prefix
                    self.results["phone_prefix"] = self.get_phone_prefix(country_code)
        else:
            # It's a domain or country code
            if len(self.target) == 2 and self.target.isalpha():
                # It's a country code (e.g., IR, US)
                self.get_country_info(self.target)
                self.results["phone_prefix"] = self.get_phone_prefix(self.target)
                # Try to get IP info for the domain
                self.results["ip_info"] = {"country_code": self.target}
            else:
                # It's a domain
                self.get_domain_info()
                # Try to get IP info
                try:
                    import socket

                    ip = socket.gethostbyname(self.target)
                    self.target = ip
                    self.get_ip_info()
                except:
                    log_warning("Could not resolve domain to IP")

        log_success("Public info gathering completed.")
        return {
            "target": self.target,
            "scan_type": "public_info",
            "results": self.results,
        }
