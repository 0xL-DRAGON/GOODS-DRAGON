# -*- coding: utf-8 -*-
import socket

import dns.resolver
import requests

from core.logger import log_debug


def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None


def check_http_status(subdomain, timeout=3):
    urls = [f"http://{subdomain}", f"https://{subdomain}"]
    for url in urls:
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            return url, response.status_code
        except:
            continue
    return None, None
