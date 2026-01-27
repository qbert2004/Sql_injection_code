"""Audit log persistence for compliance and analysis."""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sql_injection_protector.core.result import Decision, DetectionResult

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """An audit log entry."""

    timestamp: datetime
    event_type: str
    request_id: str
    client_ip: str
    action: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "request_id": self.request_id,
            "client_ip": self.client_ip,
            "action": self.action,
            "details": self.details,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Audit logger for compliance and forensic analysis.

    Features:
    - File-based logging (JSON lines format)
    - Structured logging for easy querying
    - Retention policy support
    - Optional database persistence
    """

    def __init__(
        self,
        log_path: Optional[str] = None,
        max_file_size_mb: int = 100,
        retention_days: int = 90,
        log_all_requests: bool = False,
    ):
        """
        Initialize audit logger.

        Args:
            log_path: Path to audit log file
            max_file_size_mb: Max file size before rotation
            retention_days: Days to retain logs
            log_all_requests: Log all requests (not just blocked)
        """
        self.log_path = Path(log_path) if log_path else None
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.retention_days = retention_days
        self.log_all_requests = log_all_requests
        self._entry_count = 0

        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    async def log_detection(
        self,
        detection_result: DetectionResult,
        client_ip: str,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
        was_blocked: bool = False,
    ) -> None:
        """
        Log a detection event.

        Args:
            detection_result: Detection result
            client_ip: Client IP address
            request_method: HTTP method
            request_path: Request path
            was_blocked: Whether request was blocked
        """
        # Only log blocked requests unless log_all_requests is True
        if not was_blocked and not self.log_all_requests:
            if detection_result.final_score < 0.3:
                return

        entry = AuditEntry(
            timestamp=datetime.utcnow(),
            event_type="detection",
            request_id=detection_result.request_id,
            client_ip=client_ip,
            action="blocked" if was_blocked else "allowed",
            details={
                "score": detection_result.final_score,
                "threat_level": detection_result.threat_level.name,
                "is_malicious": detection_result.is_malicious,
                "matched_patterns": detection_result.get_matched_patterns(),
                "request_method": request_method,
                "request_path": request_path,
                "processing_time_ms": detection_result.processing_time_ms,
            },
        )

        await self._write_entry(entry)

    async def log_decision(
        self,
        decision: Decision,
        client_ip: str,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
    ) -> None:
        """
        Log a decision event.

        Args:
            decision: Decision object
            client_ip: Client IP address
            request_method: HTTP method
            request_path: Request path
        """
        was_blocked = decision.should_block()

        entry = AuditEntry(
            timestamp=datetime.utcnow(),
            event_type="decision",
            request_id=decision.detection_result.request_id,
            client_ip=client_ip,
            action=decision.action.name,
            details={
                "score": decision.detection_result.final_score,
                "threat_level": decision.detection_result.threat_level.name,
                "response_code": decision.response_code,
                "block_reason": decision.block_reason,
                "request_method": request_method,
                "request_path": request_path,
                "rate_limited": decision.rate_limit_info.is_limited if decision.rate_limit_info else False,
                "honeypot_triggered": decision.honeypot_triggered,
            },
        )

        await self._write_entry(entry)

    async def log_rate_limit(
        self,
        client_ip: str,
        request_count: int,
        limit: int,
        was_banned: bool = False,
    ) -> None:
        """Log rate limit event."""
        entry = AuditEntry(
            timestamp=datetime.utcnow(),
            event_type="rate_limit",
            request_id="",
            client_ip=client_ip,
            action="banned" if was_banned else "limited",
            details={
                "request_count": request_count,
                "limit": limit,
                "was_banned": was_banned,
            },
        )

        await self._write_entry(entry)

    async def log_honeypot(
        self,
        client_ip: str,
        endpoint: str,
        payload: str,
        user_agent: Optional[str] = None,
    ) -> None:
        """Log honeypot hit."""
        entry = AuditEntry(
            timestamp=datetime.utcnow(),
            event_type="honeypot",
            request_id="",
            client_ip=client_ip,
            action="honeypot_triggered",
            details={
                "endpoint": endpoint,
                "payload_preview": payload[:500] if payload else "",
                "payload_length": len(payload) if payload else 0,
                "user_agent": user_agent,
            },
        )

        await self._write_entry(entry)

    async def log_model_event(
        self,
        event_type: str,
        model_version: str,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Log model-related event (deploy, rollback, retrain)."""
        entry = AuditEntry(
            timestamp=datetime.utcnow(),
            event_type=f"model_{event_type}",
            request_id="",
            client_ip="",
            action=event_type,
            details={
                "model_version": model_version,
                **(details or {}),
            },
        )

        await self._write_entry(entry)

    async def _write_entry(self, entry: AuditEntry) -> None:
        """Write entry to log file."""
        if not self.log_path:
            return

        try:
            # Check for rotation
            await self._check_rotation()

            # Write entry
            with open(self.log_path, "a") as f:
                f.write(entry.to_json() + "\n")

            self._entry_count += 1

        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    async def _check_rotation(self) -> None:
        """Check if log file needs rotation."""
        if not self.log_path or not self.log_path.exists():
            return

        if self.log_path.stat().st_size > self.max_file_size:
            await self._rotate()

    async def _rotate(self) -> None:
        """Rotate the log file."""
        if not self.log_path:
            return

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        rotated_path = self.log_path.with_suffix(f".{timestamp}.log")

        try:
            self.log_path.rename(rotated_path)
            logger.info(f"Rotated audit log to {rotated_path}")
        except Exception as e:
            logger.error(f"Failed to rotate audit log: {e}")

    async def cleanup_old_logs(self) -> int:
        """
        Clean up logs older than retention period.

        Returns:
            Number of files deleted
        """
        if not self.log_path:
            return 0

        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        deleted = 0

        for log_file in self.log_path.parent.glob(f"{self.log_path.stem}*.log"):
            try:
                mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if mtime < cutoff:
                    log_file.unlink()
                    deleted += 1
            except Exception as e:
                logger.error(f"Failed to delete old log {log_file}: {e}")

        if deleted > 0:
            logger.info(f"Cleaned up {deleted} old audit log files")

        return deleted

    async def search_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_type: Optional[str] = None,
        client_ip: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Search audit logs.

        Args:
            start_time: Start time filter
            end_time: End time filter
            event_type: Event type filter
            client_ip: Client IP filter
            action: Action filter
            limit: Maximum results

        Returns:
            List of matching log entries
        """
        if not self.log_path or not self.log_path.exists():
            return []

        results = []

        try:
            with open(self.log_path) as f:
                for line in f:
                    if len(results) >= limit:
                        break

                    try:
                        entry = json.loads(line.strip())

                        # Apply filters
                        if start_time:
                            entry_time = datetime.fromisoformat(entry["timestamp"])
                            if entry_time < start_time:
                                continue

                        if end_time:
                            entry_time = datetime.fromisoformat(entry["timestamp"])
                            if entry_time > end_time:
                                continue

                        if event_type and entry.get("event_type") != event_type:
                            continue

                        if client_ip and entry.get("client_ip") != client_ip:
                            continue

                        if action and entry.get("action") != action:
                            continue

                        results.append(entry)

                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.error(f"Failed to search audit logs: {e}")

        return results

    def get_stats(self) -> dict[str, Any]:
        """Get audit logger statistics."""
        stats = {
            "log_path": str(self.log_path) if self.log_path else None,
            "entries_written": self._entry_count,
            "log_all_requests": self.log_all_requests,
        }

        if self.log_path and self.log_path.exists():
            stats["file_size_mb"] = round(self.log_path.stat().st_size / (1024 * 1024), 2)

        return stats
