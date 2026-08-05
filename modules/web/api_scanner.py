#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
from core.logger import log_info, log_success, log_warning, log_error

class APIScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.results = []

    def check_swagger(self):
        paths = ["/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/v1/api-docs", "/openapi.json"]
        for path in paths:
            url = f"{self.target}{path}"
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    if "paths" in data or "endpoints" in data:
                        log_success(f"Found Swagger/OpenAPI docs: {url}")
                        self.results.append({"type": "swagger", "url": url, "status": "exposed"})
                        return
            except:
                pass

    def check_graphql(self):
        paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]
        for path in paths:
            url = f"{self.target}{path}"
            query = '{"query":"{__typename}"}'
            headers = {"Content-Type": "application/json"}
            try:
                resp = requests.post(url, data=query, headers=headers, timeout=5)
                if resp.status_code == 200 and "data" in resp.json():
                    log_success(f"Found GraphQL endpoint: {url}")
                    self.results.append({"type": "graphql", "url": url, "status": "exposed"})
                    return
            except:
                pass

    def check_common_apis(self):
        paths = ["/api/v1", "/api/v2", "/api/v3", "/rest/api", "/api/rest", "/api/", "/v1", "/v2"]
        for path in paths:
            url = f"{self.target}{path}"
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 404:
                    log_success(f"Found API endpoint: {url} ({resp.status_code})")
                    self.results.append({"type": "api_endpoint", "url": url, "status": resp.status_code})
            except:
                pass

    def check_cors(self):
        try:
            resp = requests.get(self.target, headers={"Origin": "https://evil.com"})
            if "access-control-allow-origin" in resp.headers:
                acao = resp.headers["access-control-allow-origin"]
                if acao == "*" or acao == "https://evil.com":
                    log_success(f"CORS misconfiguration detected: {acao}")
                    self.results.append({"type": "cors", "value": acao, "status": "vulnerable"})
        except:
            pass

    def run(self):
        log_info(f"Starting API Scanner on: {self.target}")
        self.check_swagger()
        self.check_graphql()
        self.check_common_apis()
        self.check_cors()
        log_success(f"API scan completed. Found {len(self.results)} items.")
        return {
            "target": self.target,
            "scan_type": "api_scanner",
            "total_found": len(self.results),
            "results": self.results
        }
