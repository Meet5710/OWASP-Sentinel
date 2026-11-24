"""OWASP Sentinel - Path Finder Fast State Store & Redis Integration

Provides sub-millisecond control flag tracking (PAUSED, CANCELLED, RUNNING)
and live scan metrics with automatic Redis integration and thread-safe in-memory fallback.
"""

from datetime import datetime, timezone
import json
import logging
import threading
import time
from typing import Any, Dict, Optional

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)


class PathFinderStateStore:
    """High-speed state store tracking live control flags and runtime metrics for Path Finder scans."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._lock = threading.Lock()
        self._memory_flags: Dict[str, str] = {}
        self._memory_metrics: Dict[str, Dict[str, Any]] = {}
        self._redis_client: Optional[redis.Redis] = None
        self._last_redis_check: float = 0.0
        self._redis_available: bool = False

    def _get_redis(self) -> Optional[redis.Redis]:
        """Lazy-initialize Redis client with cached availability check to prevent connection overhead."""
        now = time.monotonic()
        if now - self._last_redis_check < 5.0 and not self._redis_available:
            return None

        if self._redis_client is None:
            try:
                self._redis_client = redis.Redis.from_url(
                    self.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=0.3,
                    socket_timeout=0.3,
                )
            except Exception:
                self._redis_client = None

        if self._redis_client is not None:
            try:
                self._redis_client.ping()
                self._redis_available = True
            except Exception:
                self._redis_available = False
            self._last_redis_check = now

        return self._redis_client if self._redis_available else None

    def is_redis_available(self) -> bool:
        """Return True if the Redis backend is reachable."""
        return self._get_redis() is not None

    def set_control_flag(self, scan_id: str, flag: str) -> None:
        """Set execution control flag (RUNNING, PAUSED, CANCELLED) in Redis and in-memory store."""
        normalized_flag = flag.upper().strip()
        with self._lock:
            self._memory_flags[scan_id] = normalized_flag

        r = self._get_redis()
        if r:
            try:
                r.set(f"pathfinder:scan:{scan_id}:control", normalized_flag, ex=86400)
            except Exception as e:
                logger.debug("Redis error setting control flag for %s: %s", scan_id, e)

    def get_control_flag(self, scan_id: str) -> str:
        """Fetch current control flag for a scan. Defaults to RUNNING if not set."""
        r = self._get_redis()
        if r:
            try:
                val = r.get(f"pathfinder:scan:{scan_id}:control")
                if val:
                    with self._lock:
                        self._memory_flags[scan_id] = val
                    return val
            except Exception as e:
                logger.debug("Redis error getting control flag for %s: %s", scan_id, e)

        with self._lock:
            return self._memory_flags.get(scan_id, "RUNNING")

    def set_metrics(self, scan_id: str, metrics: Dict[str, Any]) -> None:
        """Update live scan runtime metrics (progress_percent, requests_per_second, etc.)."""
        payload = {
            **metrics,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._memory_metrics[scan_id] = payload

        r = self._get_redis()
        if r:
            try:
                r.set(f"pathfinder:scan:{scan_id}:metrics", json.dumps(payload), ex=86400)
            except Exception as e:
                logger.debug("Redis error setting metrics for %s: %s", scan_id, e)

    def get_metrics(self, scan_id: str) -> Dict[str, Any]:
        """Fetch latest runtime metrics for a scan."""
        r = self._get_redis()
        if r:
            try:
                raw = r.get(f"pathfinder:scan:{scan_id}:metrics")
                if raw:
                    data = json.loads(raw)
                    with self._lock:
                        self._memory_metrics[scan_id] = data
                    return data
            except Exception as e:
                logger.debug("Redis error getting metrics for %s: %s", scan_id, e)

        with self._lock:
            return self._memory_metrics.get(scan_id, {})

    def clear_scan(self, scan_id: str) -> None:
        """Purge state keys for a finished or deleted scan."""
        with self._lock:
            self._memory_flags.pop(scan_id, None)
            self._memory_metrics.pop(scan_id, None)

        r = self._get_redis()
        if r:
            try:
                r.delete(
                    f"pathfinder:scan:{scan_id}:control",
                    f"pathfinder:scan:{scan_id}:metrics",
                )
            except Exception:
                pass


# Global singleton instance
state_store = PathFinderStateStore()

