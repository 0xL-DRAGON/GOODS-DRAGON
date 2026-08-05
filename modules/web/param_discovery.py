#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.core.http_client import HTTPClient
from core.logger import log_info, log_success, log_warning, log_debug

class ParameterDiscovery:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        
        # Extended parameter list (200+ common parameters)
        self.common_params = [
            'id', 'user', 'page', 'cat', 'product', 'order', 'ref', 'doc', 'file', 'item',
            'q', 's', 'search', 'query', 'keyword', 'term', 'key', 'keys',
            'url', 'link', 'path', 'dest', 'redirect', 'return', 'next',
            'name', 'email', 'phone', 'mobile', 'address', 'city', 'state', 'zip',
            'page_id', 'post_id', 'article_id', 'news_id', 'blog_id',
            'action', 'cmd', 'command', 'exec', 'run', 'execute',
            'data', 'json', 'xml', 'api', 'v1', 'v2', 'v3', 'v4',
            'token', 'api_key', 'secret', 'auth', 'auth_token',
            'debug', 'test', 'dev', 'stage', 'prod', 'staging',
            'offset', 'limit', 'sort', 'filter', 'where', 'having',
            'group_by', 'order_by', 'asc', 'desc', 'count', 'list',
            'view', 'load', 'get', 'set', 'del', 'delete', 'update',
            'create', 'edit', 'remove', 'save', 'export', 'import',
            'upload', 'download', 'filepath', 'filename', 'content',
            'body', 'title', 'head', 'tag', 'category', 'type',
            'status', 'active', 'enable', 'disable', 'start', 'end',
            'from', 'to', 'date', 'time', 'datetime', 'timestamp',
            'format', 'callback', 'method', 'mode', 'option', 'options',
            'param', 'params', 'argument', 'args', 'variable', 'var',
            'id_user', 'id_product', 'id_order', 'id_cart', 'id_session',
            'user_id', 'product_id', 'order_id', 'cart_id', 'session_id'
        ]

    def test_param(self, param, value="1"):
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        resp = self.client.get(test_url)
        if resp and resp.status_code == 200:
            self.found_params.append({
                "param": param,
                "value": value,
                "status": resp.status_code,
                "content_length": len(resp.text)
            })
            log_success(f"✅ Found parameter: {param}")
            return True
        elif self.verbose and resp:
            log_debug(f"Param {param} -> {resp.status_code}")
        return False

    def run(self):
        log_info(f"Starting Parameter Discovery on: {self.target}")
        log_info(f"Testing {len(self.common_params)} common parameters...")
        self.found_params = []
        
        for param in self.common_params:
            self.test_param(param)
        
        log_success(f"Found {len(self.found_params)} parameters.")
        return {
            "target": self.target,
            "scan_type": "param_discovery",
            "total_found": len(self.found_params),
            "parameters": self.found_params
        }
