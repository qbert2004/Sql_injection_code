"""Request context dataclass for Layer 1: Request Gateway."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import hashlib
import uuid


@dataclass
class RequestContext:
    """
    Context object containing all request information.

    Extracted from WSGI/ASGI request by adapters and passed through all layers.
    """

    # Request identification
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Client information
    client_ip: str = ""
    client_port: int = 0
    user_agent: str = ""

    # Request metadata
    method: str = "GET"
    path: str = "/"
    full_url: str = ""
    protocol: str = "HTTP/1.1"

    # Headers
    headers: dict[str, str] = field(default_factory=dict)

    # Query parameters (raw strings)
    query_params: dict[str, str] = field(default_factory=dict)
    query_string: str = ""

    # Body
    body: bytes = b""
    body_text: str = ""
    content_type: str = ""

    # Cookies
    cookies: dict[str, str] = field(default_factory=dict)

    # Session information
    session_id: Optional[str] = None
    user_id: Optional[str] = None

    # Processing metadata
    is_honeypot: bool = False
    preprocessing_applied: bool = False
    normalized_inputs: dict[str, str] = field(default_factory=dict)

    # Additional context
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Compute derived fields after initialization."""
        if not self.session_id and self.cookies.get("session_id"):
            self.session_id = self.cookies["session_id"]

    def get_client_fingerprint(self) -> str:
        """Generate a fingerprint for the client based on available info."""
        parts = [
            self.client_ip,
            self.user_agent,
            self.headers.get("Accept-Language", ""),
            self.headers.get("Accept-Encoding", ""),
        ]
        fingerprint_str = "|".join(parts)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    def get_rate_limit_key(self) -> str:
        """Get the key to use for rate limiting."""
        if self.user_id:
            return f"user:{self.user_id}"
        if self.session_id:
            return f"session:{self.session_id}"
        return f"ip:{self.client_ip}"

    def get_all_inputs(self) -> list[tuple[str, str, str]]:
        """
        Get all input sources that should be analyzed.

        Returns:
            List of tuples: (source_name, field_name, value)
        """
        inputs = []

        # Query parameters
        for key, value in self.query_params.items():
            inputs.append(("query", key, value))

        # Body (if text)
        if self.body_text:
            inputs.append(("body", "raw", self.body_text))

        # Cookies (selective - only suspicious ones)
        for key, value in self.cookies.items():
            if len(value) > 50 or any(c in value for c in ["'", '"', "=", "-"]):
                inputs.append(("cookie", key, value))

        # Path segments
        path_parts = self.path.strip("/").split("/")
        for i, part in enumerate(path_parts):
            if len(part) > 20 or not part.isalnum():
                inputs.append(("path", f"segment_{i}", part))

        # Suspicious headers
        suspicious_headers = ["X-Forwarded-For", "Referer", "X-Custom-"]
        for header_name, value in self.headers.items():
            for suspicious in suspicious_headers:
                if suspicious.lower() in header_name.lower():
                    inputs.append(("header", header_name, value))
                    break

        return inputs

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "client_ip": self.client_ip,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "is_honeypot": self.is_honeypot,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RequestContext":
        """Create from dictionary."""
        if "timestamp" in data and isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)
