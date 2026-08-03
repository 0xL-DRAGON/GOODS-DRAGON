#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import threading
from flask import Flask, request, Response
import requests
from core.logger import log_info, log_success, log_warning, log_error

class ProxyServer:
    def __init__(self, port=8080, verbose=False):
        self.port = port
        self.verbose = verbose
        self.app = Flask(__name__)
        self.requests_log = []
        self.responses_log = []
        self.setup_routes()

    def setup_routes(self):
        @self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
        @self.app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
        def proxy(path):
            # Get target URL from request headers or query
            target_url = request.headers.get('X-Target-URL') or request.args.get('target')
            if not target_url:
                return {"error": "Missing X-Target-URL header or target parameter"}, 400

            # Forward the request
            method = request.method
            headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
            data = request.get_data()
            params = request.args if not request.args.get('target') else {k: v for k, v in request.args.items() if k != 'target'}

            # Log request
            req_log = {
                "method": method,
                "url": target_url,
                "headers": dict(headers),
                "params": dict(params),
                "data": data.decode('utf-8', errors='ignore')[:500]
            }
            self.requests_log.append(req_log)
            log_success(f"📥 {method} {target_url}")

            try:
                # Forward request
                if method == 'GET':
                    resp = requests.get(target_url, headers=headers, params=params, timeout=30)
                elif method == 'POST':
                    resp = requests.post(target_url, headers=headers, params=params, data=data, timeout=30)
                elif method == 'PUT':
                    resp = requests.put(target_url, headers=headers, params=params, data=data, timeout=30)
                elif method == 'DELETE':
                    resp = requests.delete(target_url, headers=headers, params=params, timeout=30)
                else:
                    resp = requests.request(method, target_url, headers=headers, params=params, data=data, timeout=30)

                # Log response
                res_log = {
                    "url": target_url,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "content_length": len(resp.content),
                    "preview": resp.text[:500]
                }
                self.responses_log.append(res_log)
                log_info(f"📤 {resp.status_code} {target_url}")

                # Forward response
                return Response(
                    resp.content,
                    status=resp.status_code,
                    headers=dict(resp.headers)
                )
            except Exception as e:
                log_error(f"Proxy error: {e}")
                return {"error": str(e)}, 500

    def run(self):
        log_info(f"🐉 Dragon Eye Proxy started on port {self.port}")
        log_info(f"Set browser proxy to: http://localhost:{self.port}")
        log_info(f"Use header X-Target-URL: https://example.com or ?target=https://example.com")
        self.app.run(host='0.0.0.0', port=self.port, threaded=True)

    def get_logs(self):
        return {"requests": self.requests_log[-20:], "responses": self.responses_log[-20:]}

    def clear_logs(self):
        self.requests_log = []
        self.responses_log = []
        log_success("Logs cleared")
