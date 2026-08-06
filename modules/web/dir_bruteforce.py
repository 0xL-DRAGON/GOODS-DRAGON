#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import time
from typing import Dict, List, Optional, Tuple

from core.logger import (log_debug, log_error, log_info, log_success,
                         log_warning)
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager


class DirBruteforce:
    """
    Advanced Directory & File Bruteforce Scanner
    Supports: Directory discovery, File discovery, Backup files, Backup directories,
              Admin panels, Sensitive files, Extension variations, Recursive scanning
    Combined Power: Internal wordlist (500+) + Payload Manager Integration
    """

    def __init__(
        self,
        target: str,
        wordlist_path: str = None,
        threads: int = 30,
        verbose: bool = False,
    ):
        self.target = target.rstrip("/")
        self.threads = threads
        self.verbose = verbose
        self.client = HTTPClient(timeout=15, retries=3, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.found_items = []

        # ---------- INTERNAL WORDLIST (500+ PATHS) ----------
        self.internal_wordlist = self._load_internal_wordlist()

        # ---------- LOAD WORDLIST ----------
        self.wordlist = self._load_wordlist(wordlist_path)

        # ---------- EXTENSIONS TO CHECK ----------
        self.extensions = [
            "",
            ".php",
            ".html",
            ".htm",
            ".asp",
            ".aspx",
            ".jsp",
            ".do",
            ".action",
            ".cgi",
            ".pl",
            ".py",
            ".rb",
            ".sh",
            ".txt",
            ".xml",
            ".json",
            ".yml",
            ".yaml",
            ".ini",
            ".conf",
            ".config",
            ".bak",
            ".old",
            ".backup",
            ".swp",
            ".tmp",
            ".log",
        ]

        # ---------- STATUS CODES TO CONSIDER SUCCESSFUL ----------
        self.success_codes = [200, 301, 302, 303, 307, 308, 401, 403, 405]

    def _load_internal_wordlist(self) -> List[str]:
        """Internal wordlist (500+ paths)"""
        wordlist = []

        # ----- COMMON DIRECTORIES -----
        common_dirs = [
            "admin",
            "login",
            "wp-admin",
            "backup",
            "images",
            "css",
            "js",
            "uploads",
            "files",
            "download",
            "tmp",
            "temp",
            "logs",
            "data",
            "config",
            "include",
            "src",
            "app",
            "vendor",
            "node_modules",
            "api",
            "v1",
            "v2",
            "v3",
            "test",
            "dev",
            "stage",
            "old",
            "new",
            "assets",
            "static",
            "media",
            "public",
            "private",
            "secure",
            "hidden",
            "secret",
            "internal",
            "staff",
            "employee",
            "adminpanel",
            "admincp",
            "adminarea",
            "administrator",
            "webadmin",
            "backend",
            "cms",
            "portal",
            "dashboard",
            "controlpanel",
            "control",
            "system",
            "sysadmin",
            "root",
            "superuser",
            "manager",
            "support",
            "help",
            "faq",
            "about",
            "contact",
            "team",
            "careers",
            "jobs",
            "news",
            "blog",
            "forum",
            "community",
            "chat",
            "live",
            "stream",
            "video",
            "audio",
            "music",
            "gallery",
            "photos",
            "images",
            "pics",
            "files",
            "docs",
            "documents",
            "downloads",
            "uploads",
            "backups",
            "archive",
            "temp",
            "tmp",
            "cache",
            "sessions",
            "cookies",
            "log",
            "logs",
            "debug",
            "error",
            "access",
            "audit",
            "history",
            "dumps",
            "sql",
            "mysql",
            "postgres",
            "mongo",
            "redis",
            "elastic",
            "search",
            "index",
            "sitemap",
            "robots",
            "well-known",
            ".well-known",
            "phpmyadmin",
            "pma",
            "mysqladmin",
            "phpinfo",
            "info",
            "status",
            "health",
            "ping",
            "alive",
            "test",
            "testing",
            "demo",
            "sample",
            "example",
            "dev",
            "staging",
            "stage",
            "prod",
            "production",
            "live",
            "current",
            "old",
            "new",
            "latest",
            "version",
            "releases",
            "build",
            "deploy",
            "ci",
            "cd",
            "pipeline",
            "jenkins",
            "github",
            "gitlab",
            "bitbucket",
            "svn",
            "git",
            "hg",
            "svn",
            "docs",
            "doc",
            "manual",
            "guide",
            "tutorial",
            "help",
            "support",
            "feedback",
            "bug",
            "issue",
            "ticket",
            "security",
            "privacy",
            "terms",
            "legal",
            "policy",
            "copyright",
            "license",
            "credits",
            "authors",
            "contributors",
            "api",
            "rest",
            "soap",
            "graphql",
            "odata",
            "json",
            "xml",
            "rpc",
            "ws",
            "webservice",
            "service",
            "services",
            "auth",
            "login",
            "signin",
            "signup",
            "register",
            "logout",
            "password",
            "reset",
            "forgot",
            "recover",
            "unlock",
            "profile",
            "account",
            "settings",
            "preferences",
            "config",
            "setup",
            "install",
            "update",
            "upgrade",
            "migrate",
            "seed",
            "populate",
            "init",
            "bootstrap",
            "start",
            "stop",
            "restart",
            "reload",
            "flush",
            "clear",
            "dashboard",
            "home",
            "index",
            "default",
            "main",
            "master",
            "frontend",
            "backend",
            "client",
            "server",
            "web",
            "mobile",
            "android",
            "ios",
            "iphone",
            "ipad",
            "desktop",
            "windows",
            "mac",
            "linux",
            "unix",
            "admin",
            "moderator",
            "editor",
            "author",
            "contributor",
            "subscriber",
            "member",
            "guest",
            "visitor",
            "user",
            "customer",
            "client",
            "partner",
            "vendor",
            "supplier",
            "distributor",
            "reseller",
            "affiliate",
            "referral",
            "ambassador",
        ]
        wordlist.extend(common_dirs)

        # ----- SENSITIVE FILES -----
        sensitive_files = [
            ".env",
            ".env.local",
            ".env.backup",
            ".env.example",
            ".git/config",
            ".git/HEAD",
            ".git/index",
            ".gitignore",
            ".htaccess",
            ".htpasswd",
            ".htgroups",
            ".htusers",
            ".ssh/id_rsa",
            ".ssh/id_dsa",
            ".ssh/authorized_keys",
            ".aws/credentials",
            ".aws/config",
            ".aws/credentials",
            "config.php",
            "wp-config.php",
            "settings.py",
            "settings.ini",
            "config.yml",
            "config.yaml",
            "config.json",
            "config.xml",
            "secrets.yml",
            "secrets.yaml",
            "secrets.json",
            "secrets.txt",
            "credentials.json",
            "service-account.json",
            "client_secret.json",
            ".npmrc",
            ".yarnrc",
            ".babelrc",
            ".eslintrc",
            "composer.json",
            "composer.lock",
            "package.json",
            "yarn.lock",
            "Gemfile",
            "Gemfile.lock",
            "requirements.txt",
            "Pipfile",
            "Cargo.toml",
            "go.mod",
            "go.sum",
            "pubspec.yaml",
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "Jenkinsfile",
            ".travis.yml",
            ".gitlab-ci.yml",
            ".github/workflows/main.yml",
            ".circleci/config.yml",
            ".drone.yml",
            "build.gradle",
            "pom.xml",
            "web.config",
            "app.config",
            "application.properties",
            "application.yml",
            "log4j.properties",
            "logback.xml",
            "logging.properties",
            "server.xml",
            "context.xml",
            "web.xml",
            "jboss-web.xml",
            "php.ini",
            "php.ini-production",
            "php.ini-development",
            "my.cnf",
            "my.ini",
            "postgresql.conf",
            "pg_hba.conf",
            "redis.conf",
            "mongod.conf",
            "elasticsearch.yml",
            "nginx.conf",
            "apache2.conf",
            "httpd.conf",
            ".htaccess",
            "ssh_config",
            "sshd_config",
            "known_hosts",
            "authorized_keys",
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "README.md",
            "LICENSE",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            "SECURITY.md",
            "SUPPORT.md",
        ]
        wordlist.extend(sensitive_files)

        # ----- ADMIN PANELS -----
        admin_panels = [
            "admin",
            "administrator",
            "admincp",
            "adminpanel",
            "wp-admin",
            "joomla-admin",
            "drupal-admin",
            "magento-admin",
            "cpanel",
            "whm",
            "webmail",
            "plesk",
            "directadmin",
            "phpmyadmin",
            "pma",
            "mysql",
            "myadmin",
            "adminer",
            "phpinfo",
            "info",
            "phpinfo.php",
            "info.php",
            "test.php",
            "install",
            "setup",
            "config",
            "configure",
            "install.php",
            "upgrade",
            "update",
            "migrate",
            "deploy",
            "build",
        ]
        wordlist.extend(admin_panels)

        # ----- BACKUP FILES -----
        backup_files = [
            "backup.sql",
            "backup.zip",
            "backup.tar",
            "backup.gz",
            "backup.bz2",
            "backup.7z",
            "backup.rar",
            "backup.tgz",
            "dump.sql",
            "dump.zip",
            "dump.tar",
            "dump.gz",
            "db.sql",
            "db.zip",
            "db.tar",
            "db.gz",
            "database.sql",
            "database.zip",
            "database.tar",
            "database.gz",
            "data.sql",
            "data.zip",
            "data.tar",
            "data.gz",
            "old.zip",
            "old.tar",
            "old.gz",
            "old.sql",
            "new.zip",
            "new.tar",
            "new.gz",
            "new.sql",
            "backup_old.zip",
            "backup_old.tar",
            "backup_old.gz",
            "backup_old.sql",
            "backup_new.zip",
            "backup_new.tar",
            "backup_new.gz",
            "backup_new.sql",
            "backup_2024.zip",
            "backup_2024.tar",
            "backup_2024.gz",
            "backup_2024.sql",
            "backup_2025.zip",
            "backup_2025.tar",
            "backup_2025.gz",
            "backup_2025.sql",
            "site_backup.zip",
            "site_backup.tar",
            "site_backup.gz",
            "site_backup.sql",
            "db_backup.zip",
            "db_backup.tar",
            "db_backup.gz",
            "db_backup.sql",
            "full_backup.zip",
            "full_backup.tar",
            "full_backup.gz",
            "full_backup.sql",
            "daily_backup.zip",
            "daily_backup.tar",
            "daily_backup.gz",
            "daily_backup.sql",
            "weekly_backup.zip",
            "weekly_backup.tar",
            "weekly_backup.gz",
            "weekly_backup.sql",
        ]
        wordlist.extend(backup_files)

        # ----- API ENDPOINTS -----
        api_endpoints = [
            "api",
            "api/v1",
            "api/v2",
            "api/v3",
            "api/rest",
            "rest",
            "rest/v1",
            "rest/v2",
            "rest/v3",
            "graphql",
            "graphiql",
            "api/graphql",
            "api/graphiql",
            "soap",
            "api/soap",
            "wsdl",
            "api/wsdl",
            "json",
            "api/json",
            "xml",
            "api/xml",
            "rpc",
            "api/rpc",
            "odata",
            "api/odata",
        ]
        wordlist.extend(api_endpoints)

        return list(set(wordlist))

    def _load_wordlist(self, wordlist_path: str = None) -> List[str]:
        """Load wordlist from file or use internal"""
        wordlist = []

        # Try to load from file
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, "r", encoding="utf-8") as f:
                    wordlist = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
                log_success(f"Loaded {len(wordlist)} paths from {wordlist_path}")
                return wordlist
            except Exception as e:
                if self.verbose:
                    log_debug(f"Error loading wordlist: {e}")

        # Use internal wordlist
        wordlist = self.internal_wordlist.copy()
        log_info(f"Using internal wordlist with {len(wordlist)} paths")
        return wordlist

    def check_path(self, path: str) -> Optional[Dict]:
        """Check if a path exists"""
        # Check with each extension
        for ext in self.extensions:
            test_path = path + ext
            url = f"{self.target}/{test_path}"

            resp = self.client.get(url)
            if not resp:
                continue

            if resp.status_code in self.success_codes:
                result = {
                    "path": test_path,
                    "url": url,
                    "status": resp.status_code,
                    "content_length": len(resp.text) if resp.text else 0,
                    "type": "file" if ext else "directory",
                }
                self.results.append(result)
                log_success(f"Found: {url} [{resp.status_code}]")
                return result

        return None

    def run(self) -> Dict:
        log_info(f"Starting Directory Bruteforce on: {self.target}")
        log_info(
            f"Testing {len(self.wordlist)} paths with {len(self.extensions)} extensions"
        )

        # Shuffle wordlist to avoid pattern detection
        shuffled_wordlist = self.wordlist.copy()
        random.shuffle(shuffled_wordlist)

        # Limit to 1000 for speed
        test_paths = shuffled_wordlist[:1000]
        log_info(f"Testing {len(test_paths)} paths...")

        for path in test_paths:
            self.check_path(path)

        log_success(f"Directory bruteforce completed. Found {len(self.results)} items.")
        return {
            "target": self.target,
            "scan_type": "dir_bruteforce",
            "total_tested": len(test_paths),
            "total_found": len(self.results),
            "extensions": self.extensions,
            "found_items": self.results,
        }
