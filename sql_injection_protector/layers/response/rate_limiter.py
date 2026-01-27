"""Redis-based rate limiter with sliding window algorithm."""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sql_injection_protector.core.result import RateLimitInfo
from sql_injection_protector.storage.redis import RedisClient

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limiter configuration."""

    requests_per_minute: int = 100
    requests_per_hour: int = 1000
    ban_threshold: int = 5
    ban_duration_seconds: int = 3600
    sliding_window: bool = True


class RateLimiter:
    """
    Redis-based rate limiter using sliding window algorithm.

    Features:
    - Per-minute and per-hour limits
    - Sliding window for accurate rate calculation
    - Automatic banning after threshold
    - Whitelist support
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        config: Optional[RateLimitConfig] = None,
    ):
        """
        Initialize rate limiter.

        Args:
            redis_client: Redis client for state storage
            config: Rate limit configuration
        """
        self.redis = redis_client
        self.config = config or RateLimitConfig()
        self._whitelist: set[str] = set()
        self._local_counts: dict[str, list[float]] = {}  # Fallback when Redis unavailable

    def add_to_whitelist(self, key: str) -> None:
        """Add a key to the whitelist (bypasses rate limiting)."""
        self._whitelist.add(key)

    def remove_from_whitelist(self, key: str) -> None:
        """Remove a key from the whitelist."""
        self._whitelist.discard(key)

    def is_whitelisted(self, key: str) -> bool:
        """Check if a key is whitelisted."""
        return key in self._whitelist

    async def check(self, key: str) -> RateLimitInfo:
        """
        Check rate limit for a key.

        Args:
            key: Identifier (IP, user ID, session ID)

        Returns:
            RateLimitInfo with current status
        """
        if self.is_whitelisted(key):
            return RateLimitInfo(
                is_limited=False,
                remaining=self.config.requests_per_minute,
                limit=self.config.requests_per_minute,
            )

        # Check if banned
        is_banned, ban_info = await self._check_ban(key)
        if is_banned:
            return RateLimitInfo(
                is_limited=True,
                remaining=0,
                limit=self.config.requests_per_minute,
                reset_at=datetime.fromisoformat(ban_info["timestamp"]) + timedelta(seconds=ban_info["duration"]),
                window_seconds=ban_info.get("duration", 3600),
            )

        # Check rate limits
        if self.redis and self.redis.is_connected:
            return await self._check_redis(key)
        else:
            return self._check_local(key)

    async def _check_redis(self, key: str) -> RateLimitInfo:
        """Check rate limit using Redis."""
        # Check minute limit
        is_allowed_minute, minute_count, remaining_minute = await self.redis.rate_limit_check(
            f"rate:minute:{key}",
            limit=self.config.requests_per_minute,
            window_seconds=60,
        )

        # Check hour limit
        is_allowed_hour, hour_count, remaining_hour = await self.redis.rate_limit_check(
            f"rate:hour:{key}",
            limit=self.config.requests_per_hour,
            window_seconds=3600,
        )

        is_limited = not (is_allowed_minute and is_allowed_hour)

        # Track violations for banning
        if is_limited:
            await self._track_violation(key)

        return RateLimitInfo(
            is_limited=is_limited,
            remaining=min(remaining_minute, remaining_hour),
            limit=self.config.requests_per_minute,
            reset_at=datetime.utcnow() + timedelta(seconds=60) if is_limited else None,
            window_seconds=60,
        )

    def _check_local(self, key: str) -> RateLimitInfo:
        """Check rate limit using local storage (fallback)."""
        now = time.time()

        if key not in self._local_counts:
            self._local_counts[key] = []

        # Clean old entries
        minute_ago = now - 60
        self._local_counts[key] = [t for t in self._local_counts[key] if t > minute_ago]

        # Count requests
        count = len(self._local_counts[key])

        # Add current request
        self._local_counts[key].append(now)

        is_limited = count >= self.config.requests_per_minute
        remaining = max(0, self.config.requests_per_minute - count)

        return RateLimitInfo(
            is_limited=is_limited,
            remaining=remaining,
            limit=self.config.requests_per_minute,
            reset_at=datetime.utcnow() + timedelta(seconds=60) if is_limited else None,
            window_seconds=60,
        )

    async def _check_ban(self, key: str) -> tuple[bool, Optional[dict]]:
        """Check if key is banned."""
        if self.redis and self.redis.is_connected:
            return await self.redis.rate_limit_is_banned(f"ban:{key}")
        return False, None

    async def _track_violation(self, key: str) -> None:
        """Track rate limit violation for banning."""
        if not self.redis or not self.redis.is_connected:
            return

        violation_key = f"violations:{key}"
        count = await self.redis._execute("incr", violation_key)
        await self.redis._execute("expire", violation_key, 3600)

        if count >= self.config.ban_threshold:
            await self.ban(key, reason="Rate limit violations exceeded threshold")

    async def ban(
        self,
        key: str,
        duration_seconds: Optional[int] = None,
        reason: str = "",
    ) -> None:
        """
        Ban a key from making requests.

        Args:
            key: Identifier to ban
            duration_seconds: Ban duration (uses config default if None)
            reason: Reason for ban
        """
        duration = duration_seconds or self.config.ban_duration_seconds

        if self.redis and self.redis.is_connected:
            await self.redis.rate_limit_ban(f"ban:{key}", duration, reason)
            logger.warning(f"Banned {key} for {duration}s: {reason}")

    async def unban(self, key: str) -> bool:
        """
        Remove ban from a key.

        Args:
            key: Identifier to unban

        Returns:
            True if unban successful
        """
        if self.redis and self.redis.is_connected:
            await self.redis._execute("delete", f"sqli:ban:{key}")
            logger.info(f"Unbanned {key}")
            return True
        return False

    async def get_stats(self, key: str) -> dict:
        """
        Get rate limit statistics for a key.

        Args:
            key: Identifier

        Returns:
            Statistics dictionary
        """
        if not self.redis or not self.redis.is_connected:
            count = len(self._local_counts.get(key, []))
            return {
                "minute_count": count,
                "hour_count": count,
                "is_banned": False,
                "violations": 0,
            }

        minute_count = await self.redis._execute(
            "zcount", f"sqli:rate:minute:{key}", "-inf", "+inf"
        ) or 0

        hour_count = await self.redis._execute(
            "zcount", f"sqli:rate:hour:{key}", "-inf", "+inf"
        ) or 0

        is_banned, _ = await self._check_ban(key)

        violations = await self.redis._execute("get", f"sqli:violations:{key}") or 0

        return {
            "minute_count": minute_count,
            "hour_count": hour_count,
            "is_banned": is_banned,
            "violations": int(violations),
        }

    async def reset(self, key: str) -> None:
        """
        Reset rate limit counters for a key.

        Args:
            key: Identifier to reset
        """
        if self.redis and self.redis.is_connected:
            await self.redis._execute("delete", f"sqli:rate:minute:{key}")
            await self.redis._execute("delete", f"sqli:rate:hour:{key}")
            await self.redis._execute("delete", f"sqli:violations:{key}")

        if key in self._local_counts:
            del self._local_counts[key]


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that adjusts limits based on behavior.

    Features:
    - Automatic limit adjustment based on historical behavior
    - Gradual recovery after good behavior
    - Stricter limits for suspicious patterns
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        config: Optional[RateLimitConfig] = None,
        min_limit: int = 10,
        max_limit: int = 500,
    ):
        super().__init__(redis_client, config)
        self.min_limit = min_limit
        self.max_limit = max_limit

    async def get_adaptive_limit(self, key: str) -> int:
        """Get adaptive limit for a key based on history."""
        if not self.redis or not self.redis.is_connected:
            return self.config.requests_per_minute

        # Get historical data
        good_requests = await self.redis._execute("get", f"sqli:good:{key}") or 0
        bad_requests = await self.redis._execute("get", f"sqli:bad:{key}") or 0

        good_count = int(good_requests)
        bad_count = int(bad_requests)

        if bad_count == 0 and good_count > 100:
            # Good history, increase limit
            return min(self.max_limit, self.config.requests_per_minute * 2)
        elif bad_count > 0:
            # Bad history, decrease limit
            ratio = bad_count / (good_count + bad_count + 1)
            multiplier = max(0.1, 1.0 - ratio)
            return max(self.min_limit, int(self.config.requests_per_minute * multiplier))

        return self.config.requests_per_minute

    async def record_request(self, key: str, is_malicious: bool) -> None:
        """Record request outcome for adaptive limits."""
        if not self.redis or not self.redis.is_connected:
            return

        if is_malicious:
            await self.redis._execute("incr", f"sqli:bad:{key}")
        else:
            await self.redis._execute("incr", f"sqli:good:{key}")

        # Set expiry (30 days)
        await self.redis._execute("expire", f"sqli:bad:{key}", 2592000)
        await self.redis._execute("expire", f"sqli:good:{key}", 2592000)
