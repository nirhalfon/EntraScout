"""Async HTTP client with stealth knobs (UA rotation, jitter, QPS, proxy)."""
from __future__ import annotations

import asyncio
import random
import ssl
import time
from typing import Any

import httpx

# Plausible MS-client User-Agents.
USER_AGENTS = [
    # Outlook desktop
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17029; Pro)",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Teams desktop
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Teams/24129.1414.2925.6017 Chrome/120.0.0.0 Electron/28.2.10 Safari/537.36",
    # Mobile Safari (iOS Outlook)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Mobile/15E148 Outlook-iOS/722.0.0",
    # Generic Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
]


class StealthClient:
    """httpx.AsyncClient wrapper with QPS/jitter and UA rotation."""

    def __init__(
        self,
        timeout: float = 8.0,
        qps: float | None = None,
        jitter: float = 0.25,
        proxy: str | None = None,
        verify_ssl: bool = True,
        user_agent: str | None = None,
        history_writer: Any = None,
        logger: Any = None,
    ) -> None:
        self.timeout = timeout
        self.qps = qps
        self.jitter = jitter
        self._next_slot: float = 0.0
        self._lock = asyncio.Lock()
        self._user_agent = user_agent
        self._history = history_writer
        self._log = logger

        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=ctx,
            follow_redirects=True,
            http2=True,
            proxy=proxy,
            headers={
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

    @property
    def client(self) -> httpx.AsyncClient:
        return self._client

    def _ua(self) -> str:
        return self._user_agent or random.choice(USER_AGENTS)

    async def _throttle(self) -> None:
        if self.qps is None or self.qps <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            interval = 1.0 / self.qps
            wait = max(0.0, self._next_slot - now)
            if wait > 0:
                await asyncio.sleep(wait + random.uniform(0, self.jitter * interval))
            self._next_slot = max(now, self._next_slot) + interval

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        data: Any = None,
        timeout: float | None = None,
    ) -> httpx.Response | None:
        await self._throttle()
        h = {"User-Agent": self._ua()}
        if headers:
            h.update(headers)
        start = time.monotonic()
        resp: httpx.Response | None = None
        err: str | None = None
        try:
            resp = await self._client.request(
                method,
                url,
                headers=h,
                params=params,
                json=json,
                data=data,
                timeout=timeout or self.timeout,
            )
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as e:
            err = f"{type(e).__name__}: {e}"
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
        elapsed_ms = int((time.monotonic() - start) * 1000)
        if self._log:
            self._log.debug("HTTP %s %s -> %s (%dms)", method, url,
                            resp.status_code if resp else err, elapsed_ms)
        if self._history:
            self._history.emit({
                "type": "http",
                "method": method,
                "url": url,
                "status": resp.status_code if resp else None,
                "elapsed_ms": elapsed_ms,
                "ua": h.get("User-Agent", ""),
                "request_headers": {k: v for k, v in h.items() if k.lower() != "authorization"},
                "response_headers": dict(resp.headers) if resp else {},
                "error": err,
            })
        return resp

    async def get(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("HEAD", url, **kw)

    async def post(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> StealthClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
