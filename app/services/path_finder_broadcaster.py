"""OWASP Sentinel - Path Finder Real-Time Event Broadcaster

Manages Server-Sent Events (SSE) and WebSocket subscriber channels
for pushing newly discovered paths, progress percentage, requests/sec,
and status transitions in real time.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, AsyncGenerator, Dict, Optional, Set

from app.services.path_finder_state import state_store

logger = logging.getLogger(__name__)


class ScanEventBroadcaster:
    """Asynchronous pub/sub broadcaster distributing scan events to SSE and WebSocket clients."""

    def __init__(self):
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, scan_id: str) -> asyncio.Queue:
        """Register a subscriber queue for real-time events on scan_id."""
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        async with self._lock:
            if scan_id not in self._subscribers:
                self._subscribers[scan_id] = set()
            self._subscribers[scan_id].add(q)
        return q

    async def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        """Remove a subscriber queue when client disconnects."""
        async with self._lock:
            if scan_id in self._subscribers:
                self._subscribers[scan_id].discard(q)
                if not self._subscribers[scan_id]:
                    del self._subscribers[scan_id]

    def publish(self, scan_id: str, event_type: str, data: Dict[str, Any]) -> None:
        """Dispatch an event payload to all active subscribers of scan_id without blocking."""
        message = {
            "type": event_type,
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **data,
        }

        # 1. Distribute to in-memory subscriber queues
        queues = list(self._subscribers.get(scan_id, []))
        for q in queues:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                # If a client is slow, evict one item to maintain live stream
                try:
                    q.get_nowait()
                    q.put_nowait(message)
                except Exception:
                    pass
            except Exception as e:
                logger.debug("Broadcaster error delivering to queue for %s: %s", scan_id, e)

        # 2. Redis Pub/Sub if available
        r = state_store._get_redis()
        if r:
            try:
                r.publish(f"pathfinder:channel:{scan_id}", json.dumps(message))
            except Exception as e:
                logger.debug("Redis publish error for %s: %s", scan_id, e)

    @staticmethod
    def format_sse(event_type: str, data: Dict[str, Any]) -> str:
        """Format an event dictionary into RFC-standard SSE wire format."""
        json_data = json.dumps(data)
        return f"event: {event_type}\ndata: {json_data}\n\n"


# Global singleton instance
broadcaster = ScanEventBroadcaster()

