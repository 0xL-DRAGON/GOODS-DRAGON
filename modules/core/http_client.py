#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import time
import requests
import cloudscraper
from modules.core.user_agents import get_random_user_agent
from modules.core.async_http import AsyncHTTPClient
from core.logger import log_info, log_warning, log_error, log_debug

class HTTPClient:
    def __init__(self, timeout=20, retries=5, use_cloudscraper=True, rotate_ua=True, proxy_list=None, verbose=False):
        self.timeout = timeout
        self.retries = retries
        self.use_cloudscraper = use_cloudscraper
        self.rotate_ua = rotate_ua
        self.proxy_list = proxy_list or []
        self.verbose = verbose
        self.session = self._create_session()
        self._cookies = {}

    def _create_session(self):
        if self.use_cloudscraper:
            return cloudscraper.create_scraper()
        session = requests.Session()
        session.headers.update(self._get_headers())
        return session

    def _get_headers(self):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0"
        }
        if self.rotate_ua:
            headers["User-Agent"] = get_random_user_agent()
        return headers

    def _get_proxy(self):
        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            return {"http": proxy, "https": proxy}
        return None

    def _random_delay(self, min_delay=1.0, max_delay=5.0):
        if self.verbose:
            delay = random.uniform(min_delay, max_delay)
            log_debug(f"Sleeping for {delay:.2f} seconds...")
            time.sleep(delay)
        else:
            time.sleep(random.uniform(min_delay, max_delay))

    def _add_random_params(self, url):
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params['_'] = [str(random.randint(100000, 999999))]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _should_retry(self, status_code):
        return status_code in [403, 429, 447, 503, 504]

    def request(self, method, url, params=None, data=None, json=None, headers=None, **kwargs):
        url = self._add_random_params(url)
        _headers = self._get_headers()
        if headers:
            _headers.update(headers)
        
        proxy = self._get_proxy()
        timeout = kwargs.get('timeout', self.timeout)
        
        for attempt in range(self.retries):
            try:
                if self.rotate_ua:
                    _headers["User-Agent"] = get_random_user_agent()
                
                if self.verbose:
                    log_debug(f"Request {attempt+1}/{self.retries}: {method} {url}")
                
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json,
                    headers=_headers,
                    proxies=proxy,
                    timeout=timeout,
                    **{k: v for k, v in kwargs.items() if k not in ['timeout']}
                )
                
                if self._should_retry(resp.status_code):
                    log_warning(f"Blocked ({resp.status_code}), retrying... ({attempt+1}/{self.retries})")
                    self._random_delay(2.0, 8.0)
                    continue
                
                if self.verbose:
                    log_debug(f"Response: {resp.status_code} ({len(resp.content)} bytes)")
                
                return resp
                
            except requests.exceptions.Timeout:
                log_warning(f"Timeout, retrying... ({attempt+1}/{self.retries})")
                self._random_delay(1.0, 4.0)
            except requests.exceptions.ConnectionError:
                log_warning(f"Connection error, retrying... ({attempt+1}/{self.retries})")
                self._random_delay(2.0, 6.0)
            except Exception as e:
                log_error(f"Request failed: {e}, retrying... ({attempt+1}/{self.retries})")
                self._random_delay(1.0, 3.0)
        
        log_error(f"All {self.retries} attempts failed for {url}")
        return None

    def get(self, url, params=None, **kwargs):
        return self.request('GET', url, params=params, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.request('POST', url, data=data, json=json, **kwargs)

    def head(self, url, **kwargs):
        return self.request('HEAD', url, **kwargs)

    def put(self, url, data=None, **kwargs):
        return self.request('PUT', url, data=data, **kwargs)

    def delete(self, url, **kwargs):
        return self.request('DELETE', url, **kwargs)

    def get_async(self, url, params=None):
        """Fetch content asynchronously (faster) using AsyncHTTPClient"""
        client = AsyncHTTPClient(
            timeout=self.timeout,
            retries=self.retries,
            proxy_list=self.proxy_list,
            verbose=self.verbose
        )
        results = client.run_async([url])
        if results and not isinstance(results[0], Exception):
            return results[0]
        return None

    def get_async_bulk(self, urls, params_list=None):
        """Fetch multiple URLs asynchronously"""
        if params_list is None:
            params_list = [None] * len(urls)
        
        client = AsyncHTTPClient(
            timeout=self.timeout,
            retries=self.retries,
            proxy_list=self.proxy_list,
            verbose=self.verbose
        )
        
        full_urls = []
        for i, url in enumerate(urls):
            if params_list[i]:
                import urllib.parse
                parsed = urllib.parse.urlparse(url)
                base_params = urllib.parse.parse_qs(parsed.query)
                base_params.update(params_list[i])
                new_query = urllib.parse.urlencode(base_params, doseq=True)
                full_urls.append(urllib.parse.urlunparse(parsed._replace(query=new_query)))
            else:
                full_urls.append(url)
        
        results = client.run_async(full_urls)
        client.close()
        
        return results
