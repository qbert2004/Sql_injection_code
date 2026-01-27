"""Honeypot endpoints for attack detection and payload collection."""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from sql_injection_protector.layers.request.context import RequestContext
from sql_injection_protector.storage.redis import RedisClient

logger = logging.getLogger(__name__)


@dataclass
class HoneypotEndpoint:
    """Configuration for a honeypot endpoint."""

    path: str
    method: str = "GET"
    response_template: Optional[str] = None
    collect_payload: bool = True
    delay_seconds: float = 0.0
    fake_vulnerability: str = "sqli"  # sqli, xss, rce, etc.


@dataclass
class HoneypotHit:
    """Record of a honeypot hit."""

    timestamp: datetime
    endpoint: str
    client_ip: str
    user_agent: str
    payload: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "endpoint": self.endpoint,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "payload": self.payload,
            "method": self.method,
            "headers": self.headers,
            "metadata": self.metadata,
        }


class HoneypotManager:
    """
    Manages honeypot endpoints for detecting and collecting attack payloads.

    Features:
    - Configurable fake endpoints
    - Payload collection for analysis
    - Realistic fake responses
    - Attack pattern detection
    """

    # Default honeypot endpoints
    DEFAULT_ENDPOINTS = [
        HoneypotEndpoint(path="/admin", fake_vulnerability="auth"),
        HoneypotEndpoint(path="/wp-admin", fake_vulnerability="wordpress"),
        HoneypotEndpoint(path="/phpmyadmin", fake_vulnerability="sqli"),
        HoneypotEndpoint(path="/.env", fake_vulnerability="info_disclosure"),
        HoneypotEndpoint(path="/.git/config", fake_vulnerability="info_disclosure"),
        HoneypotEndpoint(path="/config.php", fake_vulnerability="info_disclosure"),
        HoneypotEndpoint(path="/api/v1/admin/users", method="GET", fake_vulnerability="sqli"),
        HoneypotEndpoint(path="/debug", fake_vulnerability="info_disclosure"),
        HoneypotEndpoint(path="/backup.sql", fake_vulnerability="info_disclosure"),
        HoneypotEndpoint(path="/shell.php", fake_vulnerability="rce"),
    ]

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        endpoints: Optional[list[HoneypotEndpoint]] = None,
        enabled: bool = True,
    ):
        """
        Initialize honeypot manager.

        Args:
            redis_client: Redis client for storing collected data
            endpoints: Custom honeypot endpoints
            enabled: Whether honeypot is enabled
        """
        self.redis = redis_client
        self.endpoints = endpoints or self.DEFAULT_ENDPOINTS
        self.enabled = enabled
        self._endpoint_map: dict[str, HoneypotEndpoint] = {}
        self._hits: list[HoneypotHit] = []
        self._custom_handlers: dict[str, Callable] = {}

        # Build endpoint map
        for endpoint in self.endpoints:
            key = f"{endpoint.method}:{endpoint.path}"
            self._endpoint_map[key] = endpoint

    def add_endpoint(self, endpoint: HoneypotEndpoint) -> None:
        """Add a honeypot endpoint."""
        self.endpoints.append(endpoint)
        key = f"{endpoint.method}:{endpoint.path}"
        self._endpoint_map[key] = endpoint

    def remove_endpoint(self, path: str, method: str = "GET") -> bool:
        """Remove a honeypot endpoint."""
        key = f"{method}:{path}"
        if key in self._endpoint_map:
            endpoint = self._endpoint_map[key]
            self.endpoints.remove(endpoint)
            del self._endpoint_map[key]
            return True
        return False

    def is_honeypot(self, path: str, method: str = "GET") -> bool:
        """
        Check if a path is a honeypot endpoint.

        Args:
            path: Request path
            method: HTTP method

        Returns:
            True if path is a honeypot
        """
        if not self.enabled:
            return False

        # Exact match
        key = f"{method}:{path}"
        if key in self._endpoint_map:
            return True

        # Any method match
        any_key = f"GET:{path}"
        if any_key in self._endpoint_map:
            return True

        # Pattern matching for common attack paths
        suspicious_patterns = [
            ".php", ".asp", ".jsp", ".cgi",
            "admin", "login", "config", "backup",
            ".env", ".git", ".svn", ".htaccess",
        ]

        path_lower = path.lower()
        for pattern in suspicious_patterns:
            if pattern in path_lower:
                # Check if it's a real endpoint (would need app context)
                # For now, return True for suspicious patterns
                return any(ep.path in path for ep in self.endpoints)

        return False

    def get_endpoint(self, path: str, method: str = "GET") -> Optional[HoneypotEndpoint]:
        """Get honeypot endpoint configuration."""
        key = f"{method}:{path}"
        return self._endpoint_map.get(key)

    async def handle_hit(
        self,
        request_context: RequestContext,
    ) -> tuple[str, int, dict[str, str]]:
        """
        Handle a honeypot hit.

        Args:
            request_context: Request context

        Returns:
            Tuple of (response_body, status_code, headers)
        """
        endpoint = self.get_endpoint(request_context.path, request_context.method)

        # Record the hit
        hit = HoneypotHit(
            timestamp=datetime.utcnow(),
            endpoint=request_context.path,
            client_ip=request_context.client_ip,
            user_agent=request_context.user_agent,
            payload=request_context.query_string or request_context.body_text,
            method=request_context.method,
            headers=dict(request_context.headers),
            metadata={"request_id": request_context.request_id},
        )

        await self._store_hit(hit)

        logger.warning(
            f"Honeypot hit: {request_context.client_ip} -> {request_context.path}"
        )

        # Generate response
        if endpoint and endpoint.response_template:
            response_body = endpoint.response_template
        else:
            response_body = self._generate_fake_response(request_context, endpoint)

        # Add delay if configured
        if endpoint and endpoint.delay_seconds > 0:
            import asyncio
            await asyncio.sleep(endpoint.delay_seconds)

        headers = {
            "Content-Type": "application/json",
            "X-Powered-By": "PHP/7.4.0",  # Fake header
        }

        return response_body, 200, headers

    def _generate_fake_response(
        self,
        request_context: RequestContext,
        endpoint: Optional[HoneypotEndpoint],
    ) -> str:
        """Generate a realistic fake response."""
        vuln_type = endpoint.fake_vulnerability if endpoint else "generic"

        if vuln_type == "sqli":
            return json.dumps({
                "status": "success",
                "data": {
                    "users": [
                        {"id": 1, "username": "admin", "email": "admin@example.com", "role": "admin"},
                        {"id": 2, "username": "user1", "email": "user1@example.com", "role": "user"},
                    ],
                    "total": 2,
                }
            })
        elif vuln_type == "auth":
            return json.dumps({
                "status": "error",
                "message": "Invalid credentials",
                "debug": {
                    "query": f"SELECT * FROM users WHERE username='{request_context.query_params.get('user', 'admin')}'",
                }
            })
        elif vuln_type == "info_disclosure":
            return """# Configuration File
DB_HOST=localhost
DB_USER=root
DB_PASS=password123
SECRET_KEY=fake_secret_key_12345
DEBUG=true
"""
        elif vuln_type == "wordpress":
            return """<!DOCTYPE html>
<html>
<head><title>Login - WordPress</title></head>
<body>
<form method="post" action="">
<input type="text" name="log" />
<input type="password" name="pwd" />
<input type="submit" value="Log In" />
</form>
</body>
</html>"""
        else:
            return json.dumps({
                "status": "error",
                "message": "Access denied",
            })

    async def _store_hit(self, hit: HoneypotHit) -> None:
        """Store honeypot hit in Redis or memory."""
        self._hits.append(hit)

        # Keep only last 1000 hits in memory
        if len(self._hits) > 1000:
            self._hits = self._hits[-1000:]

        if self.redis and self.redis.is_connected:
            await self.redis.payload_push(
                payload=hit.payload,
                metadata=hit.to_dict(),
                queue_name="honeypot_hits",
            )

    async def get_recent_hits(self, limit: int = 100) -> list[HoneypotHit]:
        """Get recent honeypot hits."""
        return self._hits[-limit:]

    async def get_hits_by_ip(self, client_ip: str) -> list[HoneypotHit]:
        """Get all hits from a specific IP."""
        return [h for h in self._hits if h.client_ip == client_ip]

    async def get_hit_stats(self) -> dict[str, Any]:
        """Get honeypot hit statistics."""
        if not self._hits:
            return {
                "total_hits": 0,
                "unique_ips": 0,
                "top_endpoints": [],
                "top_ips": [],
            }

        from collections import Counter

        endpoint_counts = Counter(h.endpoint for h in self._hits)
        ip_counts = Counter(h.client_ip for h in self._hits)

        return {
            "total_hits": len(self._hits),
            "unique_ips": len(ip_counts),
            "top_endpoints": endpoint_counts.most_common(10),
            "top_ips": ip_counts.most_common(10),
        }

    def register_handler(
        self,
        path: str,
        handler: Callable[[RequestContext], tuple[str, int, dict]],
    ) -> None:
        """Register a custom handler for a honeypot endpoint."""
        self._custom_handlers[path] = handler
