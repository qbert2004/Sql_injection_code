"""Common Event Format (CEF) formatter for SIEM integration."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sql_injection_protector.core.result import Decision, DetectionResult, ThreatLevel


@dataclass
class CEFEvent:
    """A CEF-formatted security event."""

    version: int = 0
    device_vendor: str = "SQLInjectionProtector"
    device_product: str = "AI-Agent"
    device_version: str = "1.0.0"
    signature_id: str = "sqli_detected"
    name: str = "SQL Injection Detected"
    severity: int = 5
    extension: dict[str, Any] = None

    def __post_init__(self):
        if self.extension is None:
            self.extension = {}

    def format(self) -> str:
        """
        Format as CEF string.

        CEF format:
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        # Escape pipe characters in header fields
        def escape_header(value: str) -> str:
            return value.replace("\\", "\\\\").replace("|", "\\|")

        # Format extension key=value pairs
        def format_extension() -> str:
            parts = []
            for key, value in self.extension.items():
                # CEF key names should be alphanumeric
                safe_key = "".join(c for c in key if c.isalnum() or c == "_")
                # Escape special characters in values
                if isinstance(value, str):
                    safe_value = value.replace("\\", "\\\\").replace("=", "\\=")
                else:
                    safe_value = str(value)
                parts.append(f"{safe_key}={safe_value}")
            return " ".join(parts)

        header = "|".join([
            f"CEF:{self.version}",
            escape_header(self.device_vendor),
            escape_header(self.device_product),
            escape_header(self.device_version),
            escape_header(self.signature_id),
            escape_header(self.name),
            str(self.severity),
        ])

        extension = format_extension()

        return f"{header}|{extension}"


class CEFFormatter:
    """
    Formatter for converting detection results to CEF format.

    CEF (Common Event Format) is widely supported by SIEM systems
    like Splunk, QRadar, ArcSight, etc.
    """

    # CEF severity mapping from threat level
    SEVERITY_MAP = {
        ThreatLevel.NONE: 0,
        ThreatLevel.LOW: 3,
        ThreatLevel.MEDIUM: 5,
        ThreatLevel.HIGH: 7,
        ThreatLevel.CRITICAL: 10,
    }

    # CEF extension field names
    FIELD_MAP = {
        "source_ip": "src",
        "destination_ip": "dst",
        "source_port": "spt",
        "destination_port": "dpt",
        "request_method": "requestMethod",
        "request_url": "request",
        "user_agent": "requestClientApplication",
        "confidence": "cn1",
        "confidence_label": "cn1Label",
        "action": "act",
        "reason": "reason",
        "message": "msg",
        "detection_score": "cn2",
        "detection_score_label": "cn2Label",
        "request_id": "externalId",
    }

    def __init__(
        self,
        device_vendor: str = "SQLInjectionProtector",
        device_product: str = "AI-Agent",
        device_version: str = "1.0.0",
    ):
        """
        Initialize CEF formatter.

        Args:
            device_vendor: Vendor name for CEF header
            device_product: Product name for CEF header
            device_version: Version for CEF header
        """
        self.device_vendor = device_vendor
        self.device_product = device_product
        self.device_version = device_version

    def format_detection(
        self,
        detection_result: DetectionResult,
        client_ip: Optional[str] = None,
        request_method: Optional[str] = None,
        request_url: Optional[str] = None,
        user_agent: Optional[str] = None,
        action_taken: Optional[str] = None,
    ) -> str:
        """
        Format detection result as CEF string.

        Args:
            detection_result: Detection result
            client_ip: Source IP address
            request_method: HTTP method
            request_url: Request URL
            user_agent: User agent string
            action_taken: Action taken (BLOCK, ALLOW, etc.)

        Returns:
            CEF formatted string
        """
        severity = self.SEVERITY_MAP.get(detection_result.threat_level, 5)

        # Build signature ID based on detection
        if detection_result.is_malicious:
            signature_id = "sqli_detected"
            name = "SQL Injection Detected"
        else:
            signature_id = "sqli_clean"
            name = "Request Clean"

        # Build extension
        extension = {
            "cn1": int(detection_result.final_score * 100),
            "cn1Label": "confidence",
            "cn2": round(detection_result.final_score, 4),
            "cn2Label": "detection_score",
            "externalId": detection_result.request_id,
            "rt": int(detection_result.timestamp.timestamp() * 1000),
            "deviceProcessingTime": round(detection_result.processing_time_ms, 2),
        }

        if client_ip:
            extension["src"] = client_ip

        if request_method:
            extension["requestMethod"] = request_method

        if request_url:
            extension["request"] = request_url[:1000]  # Limit URL length

        if user_agent:
            extension["requestClientApplication"] = user_agent[:200]

        if action_taken:
            extension["act"] = action_taken

        # Add matched patterns
        patterns = detection_result.get_matched_patterns()
        if patterns:
            extension["msg"] = ", ".join(patterns[:5])

        # Add threat level
        extension["threatLevel"] = detection_result.threat_level.name

        event = CEFEvent(
            device_vendor=self.device_vendor,
            device_product=self.device_product,
            device_version=self.device_version,
            signature_id=signature_id,
            name=name,
            severity=severity,
            extension=extension,
        )

        return event.format()

    def format_decision(
        self,
        decision: Decision,
        client_ip: Optional[str] = None,
        request_method: Optional[str] = None,
        request_url: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """
        Format decision as CEF string.

        Args:
            decision: Decision object
            client_ip: Source IP address
            request_method: HTTP method
            request_url: Request URL
            user_agent: User agent string

        Returns:
            CEF formatted string
        """
        return self.format_detection(
            detection_result=decision.detection_result,
            client_ip=client_ip,
            request_method=request_method,
            request_url=request_url,
            user_agent=user_agent,
            action_taken=decision.action.name,
        )

    def format_rate_limit(
        self,
        client_ip: str,
        requests_count: int,
        limit: int,
        action: str = "RATE_LIMITED",
    ) -> str:
        """
        Format rate limit event as CEF string.

        Args:
            client_ip: Source IP address
            requests_count: Number of requests made
            limit: Rate limit threshold
            action: Action taken

        Returns:
            CEF formatted string
        """
        event = CEFEvent(
            device_vendor=self.device_vendor,
            device_product=self.device_product,
            device_version=self.device_version,
            signature_id="rate_limit_exceeded",
            name="Rate Limit Exceeded",
            severity=4,
            extension={
                "src": client_ip,
                "act": action,
                "cnt": requests_count,
                "limit": limit,
                "rt": int(datetime.utcnow().timestamp() * 1000),
            },
        )

        return event.format()

    def format_honeypot(
        self,
        client_ip: str,
        endpoint: str,
        payload: str,
        user_agent: Optional[str] = None,
    ) -> str:
        """
        Format honeypot hit as CEF string.

        Args:
            client_ip: Source IP address
            endpoint: Honeypot endpoint hit
            payload: Attack payload
            user_agent: User agent string

        Returns:
            CEF formatted string
        """
        extension = {
            "src": client_ip,
            "act": "HONEYPOT_TRIGGERED",
            "request": endpoint,
            "msg": payload[:500] if payload else "",
            "rt": int(datetime.utcnow().timestamp() * 1000),
        }

        if user_agent:
            extension["requestClientApplication"] = user_agent[:200]

        event = CEFEvent(
            device_vendor=self.device_vendor,
            device_product=self.device_product,
            device_version=self.device_version,
            signature_id="honeypot_triggered",
            name="Honeypot Triggered",
            severity=8,
            extension=extension,
        )

        return event.format()
