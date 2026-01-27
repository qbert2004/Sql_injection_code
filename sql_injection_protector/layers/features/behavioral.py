"""Behavioral feature extraction using Redis-backed session tracking."""

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from sql_injection_protector.storage.redis import RedisClient


@dataclass
class SessionMetrics:
    """Metrics tracked per session/client."""

    request_count_minute: int = 0
    request_count_hour: int = 0
    unique_endpoints: int = 0
    unique_params: int = 0
    session_age_seconds: float = 0.0
    avg_request_interval: float = 0.0
    payload_variance: float = 0.0
    blocked_count: int = 0
    challenge_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_count_minute": self.request_count_minute,
            "request_count_hour": self.request_count_hour,
            "unique_endpoints": self.unique_endpoints,
            "unique_params": self.unique_params,
            "session_age_seconds": self.session_age_seconds,
            "avg_request_interval": self.avg_request_interval,
            "payload_variance": self.payload_variance,
            "blocked_count": self.blocked_count,
            "challenge_count": self.challenge_count,
        }


class BehavioralFeatureExtractor:
    """
    Extracts behavioral features based on client/session history.

    Uses Redis for:
    - Request rate tracking (sliding window)
    - Session state
    - Pattern variance calculation
    - Historical blocking data

    Features include:
    - Request velocity (requests per minute/hour)
    - Session age
    - Endpoint diversity
    - Parameter variation
    - Previous blocking history
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        window_minute: int = 60,
        window_hour: int = 3600,
    ):
        """
        Initialize behavioral feature extractor.

        Args:
            redis_client: Redis client for state storage
            window_minute: Sliding window for per-minute tracking (seconds)
            window_hour: Sliding window for per-hour tracking (seconds)
        """
        self.redis = redis_client
        self.window_minute = window_minute
        self.window_hour = window_hour
        self._local_cache: dict[str, Any] = {}  # Fallback when Redis unavailable

    async def extract(
        self,
        client_id: str,
        endpoint: Optional[str] = None,
        payload: Optional[str] = None,
        update_state: bool = True,
    ) -> dict[str, float]:
        """
        Extract behavioral features for a client.

        Args:
            client_id: Client identifier (IP, session ID, user ID)
            endpoint: Current request endpoint
            payload: Current request payload
            update_state: Whether to update tracking state

        Returns:
            Dictionary of behavioral features
        """
        if self.redis and self.redis.is_connected:
            return await self._extract_with_redis(
                client_id, endpoint, payload, update_state
            )
        else:
            return self._extract_local(client_id, endpoint, payload, update_state)

    async def _extract_with_redis(
        self,
        client_id: str,
        endpoint: Optional[str],
        payload: Optional[str],
        update_state: bool,
    ) -> dict[str, float]:
        """Extract features using Redis backend."""
        now = time.time()
        features = {}

        # Keys
        minute_key = f"behavior:{client_id}:minute"
        hour_key = f"behavior:{client_id}:hour"
        session_key = f"behavior:{client_id}:session"
        endpoints_key = f"behavior:{client_id}:endpoints"
        params_key = f"behavior:{client_id}:params"
        payloads_key = f"behavior:{client_id}:payloads"
        blocked_key = f"behavior:{client_id}:blocked"

        # Get session data
        session_data = await self.redis.session_get(session_key) or {}
        first_seen = session_data.get("first_seen", now)
        last_seen = session_data.get("last_seen", now)
        request_times = session_data.get("request_times", [])

        # Request rate (minute window)
        is_allowed, minute_count, _ = await self.redis.rate_limit_check(
            minute_key, limit=10000, window_seconds=self.window_minute
        )
        features["requests_per_minute"] = float(minute_count)

        # Request rate (hour window)
        _, hour_count, _ = await self.redis.rate_limit_check(
            hour_key, limit=100000, window_seconds=self.window_hour
        )
        features["requests_per_hour"] = float(hour_count)

        # Session age
        session_age = now - first_seen
        features["session_age_seconds"] = session_age
        features["session_age_minutes"] = session_age / 60.0

        # Request interval
        if len(request_times) >= 2:
            intervals = [
                request_times[i] - request_times[i - 1]
                for i in range(1, len(request_times))
            ]
            avg_interval = sum(intervals) / len(intervals)
            features["avg_request_interval"] = avg_interval
            features["request_interval_variance"] = (
                sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                if len(intervals) > 1
                else 0.0
            )
        else:
            features["avg_request_interval"] = 0.0
            features["request_interval_variance"] = 0.0

        # Unique endpoints
        if endpoint and update_state:
            await self.redis._execute("sadd", endpoints_key, endpoint)
            await self.redis._execute("expire", endpoints_key, self.window_hour)
        unique_endpoints = await self.redis._execute("scard", endpoints_key) or 0
        features["unique_endpoints"] = float(unique_endpoints)

        # Unique parameters (hash the payload)
        if payload and update_state:
            payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
            await self.redis._execute("sadd", params_key, payload_hash)
            await self.redis._execute("expire", params_key, self.window_hour)
        unique_params = await self.redis._execute("scard", params_key) or 0
        features["unique_params"] = float(unique_params)

        # Payload variance (length-based heuristic)
        if payload:
            payload_len = len(payload)
            await self.redis._execute("rpush", payloads_key, str(payload_len))
            await self.redis._execute("ltrim", payloads_key, -100, -1)  # Keep last 100
            await self.redis._execute("expire", payloads_key, self.window_hour)

            payload_lengths = await self.redis._execute("lrange", payloads_key, 0, -1) or []
            if payload_lengths:
                lengths = [float(l) for l in payload_lengths]
                avg_len = sum(lengths) / len(lengths)
                variance = (
                    sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
                    if len(lengths) > 1
                    else 0.0
                )
                features["payload_length_variance"] = variance
                features["payload_length_avg"] = avg_len
            else:
                features["payload_length_variance"] = 0.0
                features["payload_length_avg"] = 0.0
        else:
            features["payload_length_variance"] = 0.0
            features["payload_length_avg"] = 0.0

        # Blocked/challenge history
        blocked_count = await self.redis._execute("get", blocked_key) or 0
        features["blocked_count"] = float(int(blocked_count))

        # Rate anomaly score
        features["rate_anomaly_score"] = self._calculate_rate_anomaly(
            minute_count, hour_count, session_age
        )

        # Update session state
        if update_state:
            request_times.append(now)
            request_times = request_times[-100:]  # Keep last 100
            await self.redis.session_set(
                session_key,
                {
                    "first_seen": first_seen,
                    "last_seen": now,
                    "request_times": request_times,
                },
                ttl_seconds=86400,  # 24 hours
            )

        return features

    def _extract_local(
        self,
        client_id: str,
        endpoint: Optional[str],
        payload: Optional[str],
        update_state: bool,
    ) -> dict[str, float]:
        """Extract features using local cache (fallback)."""
        now = time.time()

        # Initialize client state if needed
        if client_id not in self._local_cache:
            self._local_cache[client_id] = {
                "first_seen": now,
                "request_times": [],
                "endpoints": set(),
                "params": set(),
                "payload_lengths": [],
                "blocked_count": 0,
            }

        state = self._local_cache[client_id]

        # Clean old request times
        minute_ago = now - self.window_minute
        hour_ago = now - self.window_hour
        state["request_times"] = [t for t in state["request_times"] if t > hour_ago]

        # Count requests
        minute_requests = sum(1 for t in state["request_times"] if t > minute_ago)
        hour_requests = len(state["request_times"])

        features = {
            "requests_per_minute": float(minute_requests),
            "requests_per_hour": float(hour_requests),
            "session_age_seconds": now - state["first_seen"],
            "session_age_minutes": (now - state["first_seen"]) / 60.0,
        }

        # Request intervals
        times = state["request_times"]
        if len(times) >= 2:
            intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
            avg_interval = sum(intervals) / len(intervals)
            features["avg_request_interval"] = avg_interval
            features["request_interval_variance"] = (
                sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                if len(intervals) > 1
                else 0.0
            )
        else:
            features["avg_request_interval"] = 0.0
            features["request_interval_variance"] = 0.0

        # Update state
        if update_state:
            state["request_times"].append(now)

            if endpoint:
                state["endpoints"].add(endpoint)

            if payload:
                param_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
                state["params"].add(param_hash)
                state["payload_lengths"].append(len(payload))
                state["payload_lengths"] = state["payload_lengths"][-100:]

        features["unique_endpoints"] = float(len(state["endpoints"]))
        features["unique_params"] = float(len(state["params"]))

        # Payload variance
        if state["payload_lengths"]:
            lengths = state["payload_lengths"]
            avg_len = sum(lengths) / len(lengths)
            variance = (
                sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
                if len(lengths) > 1
                else 0.0
            )
            features["payload_length_variance"] = variance
            features["payload_length_avg"] = avg_len
        else:
            features["payload_length_variance"] = 0.0
            features["payload_length_avg"] = 0.0

        features["blocked_count"] = float(state["blocked_count"])
        features["rate_anomaly_score"] = self._calculate_rate_anomaly(
            minute_requests, hour_requests, features["session_age_seconds"]
        )

        return features

    def _calculate_rate_anomaly(
        self, minute_count: int, hour_count: int, session_age: float
    ) -> float:
        """
        Calculate rate anomaly score.

        High score indicates unusual request patterns.
        """
        score = 0.0

        # Very new session with high request rate
        if session_age < 60 and minute_count > 10:
            score += 0.3

        # Abnormally high per-minute rate
        if minute_count > 50:
            score += min(0.3, (minute_count - 50) / 100)

        # Sustained high rate
        expected_hour = minute_count * 60
        if hour_count > expected_hour * 1.5:
            score += 0.2

        return min(1.0, score)

    async def record_block(self, client_id: str) -> None:
        """Record that a request was blocked."""
        if self.redis and self.redis.is_connected:
            blocked_key = f"behavior:{client_id}:blocked"
            await self.redis._execute("incr", blocked_key)
            await self.redis._execute("expire", blocked_key, 86400)
        elif client_id in self._local_cache:
            self._local_cache[client_id]["blocked_count"] += 1

    async def get_session_metrics(self, client_id: str) -> SessionMetrics:
        """Get full session metrics for a client."""
        features = await self.extract(client_id, update_state=False)

        return SessionMetrics(
            request_count_minute=int(features.get("requests_per_minute", 0)),
            request_count_hour=int(features.get("requests_per_hour", 0)),
            unique_endpoints=int(features.get("unique_endpoints", 0)),
            unique_params=int(features.get("unique_params", 0)),
            session_age_seconds=features.get("session_age_seconds", 0.0),
            avg_request_interval=features.get("avg_request_interval", 0.0),
            payload_variance=features.get("payload_length_variance", 0.0),
            blocked_count=int(features.get("blocked_count", 0)),
        )

    def get_feature_names(self) -> list[str]:
        """Get list of all behavioral feature names."""
        return [
            "requests_per_minute",
            "requests_per_hour",
            "session_age_seconds",
            "session_age_minutes",
            "avg_request_interval",
            "request_interval_variance",
            "unique_endpoints",
            "unique_params",
            "payload_length_variance",
            "payload_length_avg",
            "blocked_count",
            "rate_anomaly_score",
        ]
