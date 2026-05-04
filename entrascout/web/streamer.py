"""SSE event streamer with per-scan async queues."""
from __future__ import annotations

import asyncio
from typing import Any


class ScanStreamer:
    def __init__(self) -> None:
        self._queues: dict[str, asyncio.Queue[dict[str, Any]]] = {}

    def register(self, run_id: str) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)
        self._queues[run_id] = q
        return q

    def unregister(self, run_id: str) -> None:
        self._queues.pop(run_id, None)

    async def put(self, run_id: str, event: dict[str, Any]) -> None:
        q = self._queues.get(run_id)
        if q:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass
