#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class GraphQLScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.results = []
        self.paths = ['/graphql', '/api/graphql', '/v1/graphql', '/graphiql', '/graphql/console']

    def check_graphql(self, path):
        url = f"{self.target}{path}"
        query = '{"query":"{__schema{types{name}}}"}'
        headers = {'Content-Type': 'application/json'}
        try:
            resp = requests.post(url, data=query, headers=headers, timeout=10, allow_redirects=False)
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data or 'errors' in data:
                    result = {
                        "url": url,
                        "type": "graphql",
                        "status": resp.status_code,
                        "response": resp.text[:200]
                    }
                    self.results.append(result)
                    log_success(f"🔥 GraphQL endpoint found: {url}")
                    return True
            elif self.verbose:
                log_debug(f"{url} -> {resp.status_code}")
        except Exception as e:
            if self.verbose:
                log_debug(f"Error checking {url}: {e}")
        return False

    def run(self):
        log_info(f"Starting GraphQL scan on: {self.target}")
        for path in self.paths:
            self.check_graphql(path)
        
        log_success(f"GraphQL scan completed. Found {len(self.results)} endpoints.")
        return {"target": self.target, "scan_type": "graphql", "total": len(self.results), "endpoints": self.results}
