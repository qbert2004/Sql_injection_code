"""Session management for tracking client state."""

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from sql_injection_protector.storage.redis import RedisClient


@dataclass
class SessionData:
    """Data stored in a session."""

    session_id: str
    created_at: datetime
    last_activity: datetime
    client_ip: str
    user_agent: str
    request_count: int = 0
    blocked_count: int = 0
    challenge_count: int = 0
    is_verified: bool = False
    trust_score: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "request_count": self.request_count,
            "blocked_count": self.blocked_count,
            "challenge_count": self.challenge_count,
            "is_verified": self.is_verified,
            "trust_score": self.trust_score,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionData":
        """Create from dictionary."""
        data = data.copy()
        if "created_at" in data and isinstance(data["created_at"], str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if "last_activity" in data and isinstance(data["last_activity"], str):
            data["last_activity"] = datetime.fromisoformat(data["last_activity"])
        return cls(**data)


class SessionManager:
    """
    Redis-backed session manager for tracking client state.

    Features:
    - Session creation and validation
    - Trust score tracking
    - Request counting
    - Session expiration
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        session_ttl_seconds: int = 3600,
        cookie_name: str = "sqli_session",
    ):
        """
        Initialize session manager.

        Args:
            redis_client: Redis client for session storage
            session_ttl_seconds: Session TTL in seconds
            cookie_name: Name of the session cookie
        """
        self.redis = redis_client
        self.session_ttl = session_ttl_seconds
        self.cookie_name = cookie_name
        self._local_sessions: dict[str, SessionData] = {}

    def generate_session_id(self) -> str:
        """Generate a secure session ID."""
        return secrets.token_urlsafe(32)

    async def create_session(
        self,
        client_ip: str,
        user_agent: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> SessionData:
        """
        Create a new session.

        Args:
            client_ip: Client IP address
            user_agent: Client user agent
            metadata: Optional additional metadata

        Returns:
            Created SessionData
        """
        session_id = self.generate_session_id()
        now = datetime.utcnow()

        session = SessionData(
            session_id=session_id,
            created_at=now,
            last_activity=now,
            client_ip=client_ip,
            user_agent=user_agent,
            metadata=metadata or {},
        )

        await self._store_session(session)

        return session

    async def get_session(self, session_id: str) -> Optional[SessionData]:
        """
        Get session by ID.

        Args:
            session_id: Session identifier

        Returns:
            SessionData or None if not found
        """
        if self.redis and self.redis.is_connected:
            data = await self.redis.session_get(f"session:{session_id}")
            if data:
                return SessionData.from_dict(data)
        else:
            return self._local_sessions.get(session_id)

        return None

    async def update_session(
        self,
        session_id: str,
        updates: dict[str, Any],
    ) -> Optional[SessionData]:
        """
        Update session data.

        Args:
            session_id: Session identifier
            updates: Fields to update

        Returns:
            Updated SessionData or None
        """
        session = await self.get_session(session_id)
        if not session:
            return None

        # Apply updates
        for key, value in updates.items():
            if hasattr(session, key):
                setattr(session, key, value)

        session.last_activity = datetime.utcnow()

        await self._store_session(session)

        return session

    async def _store_session(self, session: SessionData) -> None:
        """Store session in Redis or local storage."""
        if self.redis and self.redis.is_connected:
            await self.redis.session_set(
                f"session:{session.session_id}",
                session.to_dict(),
                ttl_seconds=self.session_ttl,
            )
        else:
            self._local_sessions[session.session_id] = session

    async def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: Session identifier

        Returns:
            True if deleted
        """
        if self.redis and self.redis.is_connected:
            await self.redis.session_delete(f"session:{session_id}")
            return True
        else:
            if session_id in self._local_sessions:
                del self._local_sessions[session_id]
                return True

        return False

    async def touch_session(self, session_id: str) -> bool:
        """
        Update session last activity time.

        Args:
            session_id: Session identifier

        Returns:
            True if session exists and was updated
        """
        session = await self.get_session(session_id)
        if session:
            session.last_activity = datetime.utcnow()
            session.request_count += 1
            await self._store_session(session)
            return True
        return False

    async def record_block(self, session_id: str) -> None:
        """Record a blocked request in the session."""
        session = await self.get_session(session_id)
        if session:
            session.blocked_count += 1
            session.trust_score = max(0.0, session.trust_score - 0.1)
            await self._store_session(session)

    async def record_challenge_pass(self, session_id: str) -> None:
        """Record successful challenge completion."""
        session = await self.get_session(session_id)
        if session:
            session.challenge_count += 1
            session.is_verified = True
            session.trust_score = min(1.0, session.trust_score + 0.2)
            await self._store_session(session)

    async def get_or_create_session(
        self,
        session_id: Optional[str],
        client_ip: str,
        user_agent: str,
    ) -> SessionData:
        """
        Get existing session or create new one.

        Args:
            session_id: Existing session ID (may be None)
            client_ip: Client IP address
            user_agent: Client user agent

        Returns:
            SessionData (existing or new)
        """
        if session_id:
            session = await self.get_session(session_id)
            if session:
                # Validate session belongs to same client
                if session.client_ip == client_ip:
                    await self.touch_session(session_id)
                    return session

        # Create new session
        return await self.create_session(client_ip, user_agent)

    async def is_session_valid(self, session_id: str) -> bool:
        """
        Check if session is valid and not expired.

        Args:
            session_id: Session identifier

        Returns:
            True if session is valid
        """
        session = await self.get_session(session_id)
        if not session:
            return False

        # Check expiration
        age = datetime.utcnow() - session.last_activity
        if age > timedelta(seconds=self.session_ttl):
            await self.delete_session(session_id)
            return False

        return True

    async def get_session_stats(self) -> dict[str, Any]:
        """Get session statistics."""
        if self.redis and self.redis.is_connected:
            # Would need to scan Redis keys
            return {"source": "redis", "stats": "unavailable"}

        active_sessions = len(self._local_sessions)
        verified_sessions = sum(
            1 for s in self._local_sessions.values() if s.is_verified
        )
        blocked_sessions = sum(
            1 for s in self._local_sessions.values() if s.blocked_count > 0
        )

        return {
            "active_sessions": active_sessions,
            "verified_sessions": verified_sessions,
            "blocked_sessions": blocked_sessions,
        }

    async def cleanup_expired(self) -> int:
        """
        Clean up expired sessions from local storage.

        Returns:
            Number of sessions cleaned up
        """
        if self.redis and self.redis.is_connected:
            # Redis handles expiration automatically
            return 0

        now = datetime.utcnow()
        expired = []

        for session_id, session in self._local_sessions.items():
            age = now - session.last_activity
            if age > timedelta(seconds=self.session_ttl):
                expired.append(session_id)

        for session_id in expired:
            del self._local_sessions[session_id]

        return len(expired)


def generate_fingerprint(client_ip: str, user_agent: str) -> str:
    """Generate a client fingerprint."""
    data = f"{client_ip}|{user_agent}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]
