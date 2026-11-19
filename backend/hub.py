"""In-process pub/sub to push live updates to SSE clients.

Ingest runs in a threadpool thread; SSE consumers are asyncio. We capture the
main loop at startup and use call_soon_threadsafe to cross the boundary safely.
"""
from __future__ import annotations
import asyncio, json
from typing import Any


class Hub:
    def __init__(self):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: set[asyncio.Queue] = set()

    def bind_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.discard(q)

    def publish(self, kind: str, data: Any):
        """Safe to call from any thread."""
        msg = {"type": kind, "data": data}
        loop = self._loop
        if loop is None:
            return
        for q in list(self._subscribers):
            loop.call_soon_threadsafe(self._offer, q, msg)

    @staticmethod
    def _offer(q: asyncio.Queue, msg):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass   # slow consumer: drop rather than block the producer


hub = Hub()
