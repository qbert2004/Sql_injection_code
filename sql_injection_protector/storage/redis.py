"""Redis client wrapper for rate limiting, session management, and caching."""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Optional, Union

from sql_injection_protector.core.exceptions import RedisConnectionError

logger = logging.getLogger(__name__)


class RedisClient:
    """
    Async Redis client wrapper with connection pooling and retry logic.

    Provides high-level methods for common operations:
    - Rate limiting (sliding window)
    - Session management
    - Payload queue
    - Caching
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        max_connections: int = 10,
        retry_attempts: int = 3,
        retry_delay: float = 0.5,
        key_prefix: str = "sqli:",
    ):
        self.url = url
        self.max_connections = max_connections
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self.key_prefix = key_prefix
        self._pool = None
        self._redis = None
        self._connected = False

    async def connect(self) -> None:
        """Establish connection to Redis."""
        try:
            import redis.asyncio as redis

            self._redis = redis.from_url(
                self.url,
                max_connections=self.max_connections,
                decode_responses=True,
            )
            # Test connection
            await self._redis.ping()
            self._connected = True
            logger.info(f"Connected to Redis at {self.url}")
        except ImportError:
            raise RedisConnectionError(
                "redis package not installed. Install with: pip install redis",
                redis_url=self.url,
            )
        except Exception as e:
            raise RedisConnectionError(
                f"Failed to connect to Redis: {e}",
                redis_url=self.url,
                details={"error": str(e)},
            )

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._connected = False
            logger.info("Disconnected from Redis")

    async def _execute(self, method: str, *args, **kwargs) -> Any:
        """Execute a Redis command with retry logic."""
        if not self._connected:
            await self.connect()

        last_error = None
        for attempt in range(self.retry_attempts):
            try:
                func = getattr(self._redis, method)
                return await func(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))

        raise RedisConnectionError(
            f"Redis command failed after {self.retry_attempts} attempts: {last_error}",
            redis_url=self.url,
        )

    def _key(self, key: str) -> str:
        """Add prefix to key."""
        return f"{self.key_prefix}{key}"

    # ─────────────────────────────────────────────────────────────────
    # Rate Limiting Methods
    # ─────────────────────────────────────────────────────────────────

    async def rate_limit_check(
        self,
        key: str,
        limit: int,
        window_seconds: int = 60,
    ) -> tuple[bool, int, int]:
        """
        Check rate limit using sliding window.

        Args:
            key: Identifier for rate limiting (e.g., IP, user_id)
            limit: Maximum requests allowed in window
            window_seconds: Time window in seconds

        Returns:
            Tuple of (is_allowed, current_count, remaining)
        """
        import time

        full_key = self._key(f"rate:{key}")
        now = time.time()
        window_start = now - window_seconds

        pipe = self._redis.pipeline()

        # Remove old entries
        pipe.zremrangebyscore(full_key, 0, window_start)
        # Add current request
        pipe.zadd(full_key, {str(now): now})
        # Count requests in window
        pipe.zcount(full_key, window_start, now)
        # Set expiry
        pipe.expire(full_key, window_seconds * 2)

        results = await pipe.execute()
        count = results[2]

        is_allowed = count <= limit
        remaining = max(0, limit - count)

        return is_allowed, count, remaining

    async def rate_limit_ban(
        self,
        key: str,
        duration_seconds: int = 3600,
        reason: str = "",
    ) -> None:
        """
        Ban a key from making requests.

        Args:
            key: Identifier to ban
            duration_seconds: Ban duration
            reason: Reason for ban
        """
        full_key = self._key(f"ban:{key}")
        ban_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "duration": duration_seconds,
            "reason": reason,
        }
        await self._execute("setex", full_key, duration_seconds, json.dumps(ban_data))

    async def rate_limit_is_banned(self, key: str) -> tuple[bool, Optional[dict]]:
        """
        Check if a key is banned.

        Returns:
            Tuple of (is_banned, ban_info)
        """
        full_key = self._key(f"ban:{key}")
        data = await self._execute("get", full_key)
        if data:
            return True, json.loads(data)
        return False, None

    # ─────────────────────────────────────────────────────────────────
    # Session Management Methods
    # ─────────────────────────────────────────────────────────────────

    async def session_set(
        self,
        session_id: str,
        data: dict[str, Any],
        ttl_seconds: int = 3600,
    ) -> None:
        """Store session data."""
        full_key = self._key(f"session:{session_id}")
        await self._execute("setex", full_key, ttl_seconds, json.dumps(data))

    async def session_get(self, session_id: str) -> Optional[dict[str, Any]]:
        """Retrieve session data."""
        full_key = self._key(f"session:{session_id}")
        data = await self._execute("get", full_key)
        if data:
            return json.loads(data)
        return None

    async def session_update(
        self,
        session_id: str,
        updates: dict[str, Any],
        ttl_seconds: int = 3600,
    ) -> None:
        """Update session data (merge with existing)."""
        existing = await self.session_get(session_id) or {}
        existing.update(updates)
        await self.session_set(session_id, existing, ttl_seconds)

    async def session_delete(self, session_id: str) -> None:
        """Delete session data."""
        full_key = self._key(f"session:{session_id}")
        await self._execute("delete", full_key)

    async def session_increment_counter(
        self,
        session_id: str,
        counter_name: str,
    ) -> int:
        """Increment a session counter."""
        full_key = self._key(f"session:{session_id}:{counter_name}")
        return await self._execute("incr", full_key)

    # ─────────────────────────────────────────────────────────────────
    # Payload Queue Methods (for learning)
    # ─────────────────────────────────────────────────────────────────

    async def payload_push(
        self,
        payload: str,
        metadata: dict[str, Any],
        queue_name: str = "payloads",
    ) -> None:
        """Push a payload to the collection queue."""
        full_key = self._key(f"queue:{queue_name}")
        data = {
            "payload": payload,
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self._execute("rpush", full_key, json.dumps(data))

    async def payload_pop(
        self,
        queue_name: str = "payloads",
        count: int = 1,
    ) -> list[dict[str, Any]]:
        """Pop payloads from the queue."""
        full_key = self._key(f"queue:{queue_name}")
        items = []
        for _ in range(count):
            data = await self._execute("lpop", full_key)
            if data:
                items.append(json.loads(data))
            else:
                break
        return items

    async def payload_queue_length(self, queue_name: str = "payloads") -> int:
        """Get the length of the payload queue."""
        full_key = self._key(f"queue:{queue_name}")
        return await self._execute("llen", full_key)

    # ─────────────────────────────────────────────────────────────────
    # Caching Methods
    # ─────────────────────────────────────────────────────────────────

    async def cache_get(self, key: str) -> Optional[Any]:
        """Get cached value."""
        full_key = self._key(f"cache:{key}")
        data = await self._execute("get", full_key)
        if data:
            return json.loads(data)
        return None

    async def cache_set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int = 300,
    ) -> None:
        """Set cached value."""
        full_key = self._key(f"cache:{key}")
        await self._execute("setex", full_key, ttl_seconds, json.dumps(value))

    async def cache_delete(self, key: str) -> None:
        """Delete cached value."""
        full_key = self._key(f"cache:{key}")
        await self._execute("delete", full_key)

    # ─────────────────────────────────────────────────────────────────
    # Metrics Methods
    # ─────────────────────────────────────────────────────────────────

    async def metrics_increment(
        self,
        metric_name: str,
        value: int = 1,
        labels: Optional[dict[str, str]] = None,
    ) -> int:
        """Increment a metric counter."""
        label_str = ""
        if labels:
            label_str = ":" + ":".join(f"{k}={v}" for k, v in sorted(labels.items()))
        full_key = self._key(f"metrics:{metric_name}{label_str}")
        return await self._execute("incrby", full_key, value)

    async def metrics_get(
        self,
        metric_name: str,
        labels: Optional[dict[str, str]] = None,
    ) -> int:
        """Get metric value."""
        label_str = ""
        if labels:
            label_str = ":" + ":".join(f"{k}={v}" for k, v in sorted(labels.items()))
        full_key = self._key(f"metrics:{metric_name}{label_str}")
        value = await self._execute("get", full_key)
        return int(value) if value else 0

    # ─────────────────────────────────────────────────────────────────
    # Utility Methods
    # ─────────────────────────────────────────────────────────────────

    async def ping(self) -> bool:
        """Check if Redis is reachable."""
        try:
            await self._execute("ping")
            return True
        except Exception:
            return False

    async def health_check(self) -> dict[str, Any]:
        """Get Redis health status."""
        try:
            info = await self._execute("info", "server")
            return {
                "connected": True,
                "url": self.url,
                "info": info,
            }
        except Exception as e:
            return {
                "connected": False,
                "url": self.url,
                "error": str(e),
            }

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected
