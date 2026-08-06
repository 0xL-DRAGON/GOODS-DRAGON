#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import random

import aiohttp

from modules.core.user_agents import get_random_user_agent


class AsyncHTTPClient:
    def __init__(self, timeout=15, retries=3, proxy_list=None, verbose=False):
        self.timeout = timeout
        self.retries = retries
        self.proxy_list = proxy_list or []
        self.verbose = verbose
        self.session = None

    async def _get_session(self):
        if not self.session:
            connector = aiohttp.TCPConnector(limit=100, ttl_dns_cache=300)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                connector=connector, timeout=timeout, headers=self._get_headers()
            )
        return self.session

    def _get_headers(self):
        return {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    async def get(self, url, params=None, **kwargs):
        session = await self._get_session()
        for attempt in range(self.retries):
            try:
                async with session.get(url, params=params, **kwargs) as resp:
                    return await resp.text()
            except Exception as e:
                if self.verbose:
                    print(f"[!] Attempt {attempt+1} failed: {e}")
                await asyncio.sleep(random.uniform(0.5, 2.0))
        return None

    async def close(self):
        if self.session:
            await self.session.close()

    async def scan_urls(self, urls):
        """اسکن چند URL به صورت همزمان"""
        tasks = [self.get(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def run_async(self, urls):
        """اجرای همزمان در یک حلقه رویداد"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(self.scan_urls(urls))
        finally:
            loop.run_until_complete(self.close())
            loop.close()
        return results
