"""
SQL Injection Incident Logger
=============================
SQLite-based incident logging system for SQL injection detection events.

Features:
    - Automatic logging of blocked/suspicious requests
    - Query history and analytics
    - Export capabilities for SIEM integration
    - Optional active learning data collection

Usage:
    from incident_logger import IncidentLogger

    logger = IncidentLogger()
    logger.log_incident(input_text, result_dict, metadata)

    # Query incidents
    incidents = logger.get_incidents(limit=100)
    stats = logger.get_statistics()
"""

import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from contextlib import contextmanager
from enum import Enum


class IncidentSeverity(Enum):
    """Incident severity levels"""
    LOW = "LOW"           # SUSPICIOUS - logged for review
    MEDIUM = "MEDIUM"     # CHALLENGE - requires verification
    HIGH = "HIGH"         # BLOCK - confirmed attack
    INFO = "INFO"         # INVALID/SAFE - informational


class IncidentLogger:
    """
    SQLite-based incident logging system.

    Stores all detection events with full context for:
    - Security monitoring and alerting
    - Forensic analysis
    - Model improvement (active learning)
    - Compliance reporting
    """

    DEFAULT_DB_PATH = "incidents.db"

    def __init__(self, db_path: Optional[str] = None, auto_cleanup_days: int = 90):
        """
        Initialize incident logger.

        Args:
            db_path: Path to SQLite database file
            auto_cleanup_days: Auto-delete incidents older than N days (0 = disabled)
        """
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self.auto_cleanup_days = auto_cleanup_days
        self._init_database()

        if auto_cleanup_days > 0:
            self._cleanup_old_incidents()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Main incidents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    input_hash TEXT NOT NULL,
                    input_text TEXT NOT NULL,
                    input_length INTEGER,

                    -- Detection results
                    decision TEXT NOT NULL,
                    action TEXT NOT NULL,
                    ensemble_score REAL,
                    rf_score REAL,
                    cnn_score REAL,
                    semantic_score REAL,
                    confidence TEXT,
                    reason TEXT,

                    -- Severity classification
                    severity TEXT DEFAULT 'INFO',

                    -- Context metadata
                    source_ip TEXT,
                    user_agent TEXT,
                    endpoint TEXT,
                    field_name TEXT,
                    session_id TEXT,
                    user_id TEXT,

                    -- Additional metadata (JSON)
                    metadata TEXT,

                    -- Feedback for active learning
                    is_false_positive BOOLEAN DEFAULT NULL,
                    reviewed_at DATETIME DEFAULT NULL,
                    reviewer_notes TEXT DEFAULT NULL
                )
            """)

            # Create indexes for common queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_decision ON incidents(decision)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_action ON incidents(action)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_severity ON incidents(severity)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_source_ip ON incidents(source_ip)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_input_hash ON incidents(input_hash)
            """)

            # Statistics summary table (updated periodically)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS daily_stats (
                    date DATE PRIMARY KEY,
                    total_requests INTEGER DEFAULT 0,
                    safe_count INTEGER DEFAULT 0,
                    invalid_count INTEGER DEFAULT 0,
                    suspicious_count INTEGER DEFAULT 0,
                    injection_count INTEGER DEFAULT 0,
                    blocked_count INTEGER DEFAULT 0,
                    unique_ips INTEGER DEFAULT 0,
                    avg_ensemble_score REAL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def _get_severity(self, action: str, decision: str) -> str:
        """Determine severity based on action and decision"""
        if action == "BLOCK":
            return IncidentSeverity.HIGH.value
        elif action == "CHALLENGE":
            return IncidentSeverity.MEDIUM.value
        elif decision == "SUSPICIOUS":
            return IncidentSeverity.LOW.value
        else:
            return IncidentSeverity.INFO.value

    def _hash_input(self, text: str) -> str:
        """Generate hash of input for deduplication"""
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def log_incident(
        self,
        input_text: str,
        result: Dict[str, Any],
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        endpoint: Optional[str] = None,
        field_name: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> int:
        """
        Log a detection incident.

        Args:
            input_text: The input that was analyzed
            result: Detection result dict from SQLInjectionEnsemble.detect()
            source_ip: Client IP address
            user_agent: Client user agent string
            endpoint: API endpoint or URL
            field_name: Form field name (e.g., 'username', 'search')
            session_id: Session identifier
            user_id: User identifier if authenticated
            metadata: Additional context as dict

        Returns:
            Incident ID
        """
        severity = self._get_severity(result.get('action', ''), result.get('decision', ''))

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO incidents (
                    input_hash, input_text, input_length,
                    decision, action, ensemble_score, rf_score, cnn_score,
                    semantic_score, confidence, reason, severity,
                    source_ip, user_agent, endpoint, field_name,
                    session_id, user_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self._hash_input(input_text),
                input_text,
                len(input_text),
                result.get('decision', 'UNKNOWN'),
                result.get('action', 'UNKNOWN'),
                result.get('score'),
                result.get('P_rf'),
                result.get('P_cnn'),
                result.get('semantic_score'),
                result.get('confidence_level'),
                result.get('reason'),
                severity,
                source_ip,
                user_agent,
                endpoint,
                field_name,
                session_id,
                user_id,
                json.dumps(metadata) if metadata else None
            ))

            return cursor.lastrowid

    def get_incidents(
        self,
        limit: int = 100,
        offset: int = 0,
        decision: Optional[str] = None,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        only_unreviewed: bool = False
    ) -> List[Dict]:
        """
        Query incidents with filters.

        Args:
            limit: Maximum number of results
            offset: Skip first N results
            decision: Filter by decision (SAFE, INVALID, SUSPICIOUS, INJECTION)
            action: Filter by action (ALLOW, LOG, CHALLENGE, BLOCK)
            severity: Filter by severity (INFO, LOW, MEDIUM, HIGH)
            source_ip: Filter by source IP
            start_date: Filter incidents after this date
            end_date: Filter incidents before this date
            only_unreviewed: Only return incidents not yet reviewed

        Returns:
            List of incident dicts
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM incidents WHERE 1=1"
            params = []

            if decision:
                query += " AND decision = ?"
                params.append(decision)

            if action:
                query += " AND action = ?"
                params.append(action)

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)

            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date.isoformat())

            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date.isoformat())

            if only_unreviewed:
                query += " AND is_false_positive IS NULL"

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)

            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict:
        """
        Get aggregated statistics.

        Args:
            start_date: Start of period
            end_date: End of period

        Returns:
            Statistics dictionary
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            date_filter = ""
            params = []

            if start_date:
                date_filter += " AND timestamp >= ?"
                params.append(start_date.isoformat())

            if end_date:
                date_filter += " AND timestamp <= ?"
                params.append(end_date.isoformat())

            # Total counts by decision
            cursor.execute(f"""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN decision = 'SAFE' THEN 1 ELSE 0 END) as safe,
                    SUM(CASE WHEN decision = 'INVALID' THEN 1 ELSE 0 END) as invalid,
                    SUM(CASE WHEN decision = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN decision = 'INJECTION' THEN 1 ELSE 0 END) as injection,
                    SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                    AVG(ensemble_score) as avg_score,
                    COUNT(DISTINCT source_ip) as unique_ips
                FROM incidents
                WHERE 1=1 {date_filter}
            """, params)

            row = cursor.fetchone()

            # Top attacking IPs
            cursor.execute(f"""
                SELECT source_ip, COUNT(*) as count
                FROM incidents
                WHERE action = 'BLOCK' AND source_ip IS NOT NULL {date_filter}
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            """, params)

            top_ips = [{"ip": r[0], "count": r[1]} for r in cursor.fetchall()]

            # Hourly distribution (last 24 hours)
            cursor.execute("""
                SELECT
                    strftime('%H', timestamp) as hour,
                    COUNT(*) as count
                FROM incidents
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
            """)

            hourly = {r[0]: r[1] for r in cursor.fetchall()}

            return {
                "total_incidents": row[0] or 0,
                "by_decision": {
                    "safe": row[1] or 0,
                    "invalid": row[2] or 0,
                    "suspicious": row[3] or 0,
                    "injection": row[4] or 0
                },
                "blocked_count": row[5] or 0,
                "average_score": round(row[6], 4) if row[6] else 0,
                "unique_ips": row[7] or 0,
                "top_attacking_ips": top_ips,
                "hourly_distribution": hourly,
                "block_rate": round((row[5] or 0) / max(row[0] or 1, 1) * 100, 2)
            }

    def mark_false_positive(
        self,
        incident_id: int,
        is_false_positive: bool,
        reviewer_notes: Optional[str] = None
    ):
        """
        Mark an incident as false positive/negative for active learning.

        Args:
            incident_id: Incident ID
            is_false_positive: True if blocked input was actually safe
            reviewer_notes: Optional notes from reviewer
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE incidents
                SET is_false_positive = ?,
                    reviewed_at = CURRENT_TIMESTAMP,
                    reviewer_notes = ?
                WHERE id = ?
            """, (is_false_positive, reviewer_notes, incident_id))

    def get_training_data(
        self,
        only_reviewed: bool = True,
        include_false_positives: bool = True
    ) -> List[Dict]:
        """
        Export data for model retraining (active learning).

        Args:
            only_reviewed: Only include manually reviewed incidents
            include_false_positives: Include false positives for correction

        Returns:
            List of training samples with corrected labels
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT input_text, decision, action, is_false_positive
                FROM incidents
                WHERE 1=1
            """

            if only_reviewed:
                query += " AND is_false_positive IS NOT NULL"

            cursor.execute(query)

            training_data = []
            for row in cursor.fetchall():
                # Determine correct label based on review
                if row[3] is True:  # False positive - was blocked but is safe
                    correct_label = 0  # Safe
                elif row[3] is False:  # Confirmed attack
                    correct_label = 1  # Injection
                else:  # Not reviewed - use original decision
                    correct_label = 1 if row[1] == 'INJECTION' else 0

                training_data.append({
                    "text": row[0],
                    "label": correct_label,
                    "original_decision": row[1],
                    "was_false_positive": row[3]
                })

            return training_data

    def export_to_siem(
        self,
        format: str = "json",
        start_date: Optional[datetime] = None,
        severity_min: str = "LOW"
    ) -> str:
        """
        Export incidents for SIEM integration.

        Args:
            format: Output format ('json', 'csv', 'cef')
            start_date: Export incidents after this date
            severity_min: Minimum severity to export

        Returns:
            Formatted export string
        """
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH"]
        min_idx = severity_order.index(severity_min)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT * FROM incidents
                WHERE severity IN (?)
            """

            valid_severities = severity_order[min_idx:]

            if start_date:
                query += " AND timestamp >= ?"
                cursor.execute(
                    query.replace("(?)", f"({','.join('?' * len(valid_severities))})"),
                    valid_severities + [start_date.isoformat()]
                )
            else:
                cursor.execute(
                    query.replace("(?)", f"({','.join('?' * len(valid_severities))})"),
                    valid_severities
                )

            incidents = [dict(row) for row in cursor.fetchall()]

        if format == "json":
            return json.dumps(incidents, indent=2, default=str)

        elif format == "csv":
            if not incidents:
                return ""

            headers = incidents[0].keys()
            lines = [",".join(headers)]

            for inc in incidents:
                values = [str(inc.get(h, "")).replace(",", ";") for h in headers]
                lines.append(",".join(values))

            return "\n".join(lines)

        elif format == "cef":
            # Common Event Format for SIEM
            cef_lines = []
            for inc in incidents:
                severity_map = {"INFO": 1, "LOW": 3, "MEDIUM": 6, "HIGH": 9}
                sev = severity_map.get(inc.get("severity"), 5)

                cef = f"CEF:0|SQLInjectionDetector|Agent|2.0|{inc.get('decision')}|SQL Injection Detection|{sev}|"
                cef += f"src={inc.get('source_ip', 'unknown')} "
                cef += f"msg={inc.get('reason', '')} "
                cef += f"cs1={inc.get('input_text', '')[:100]} cs1Label=Input "
                cef += f"cn1={inc.get('ensemble_score', 0)} cn1Label=Score"

                cef_lines.append(cef)

            return "\n".join(cef_lines)

        return json.dumps(incidents, default=str)

    def _cleanup_old_incidents(self):
        """Remove incidents older than auto_cleanup_days"""
        if self.auto_cleanup_days <= 0:
            return

        cutoff = datetime.now() - timedelta(days=self.auto_cleanup_days)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM incidents WHERE timestamp < ? AND severity = 'INFO'",
                (cutoff.isoformat(),)
            )

    def get_incident_count(self) -> int:
        """Get total number of incidents"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM incidents")
            return cursor.fetchone()[0]


# Convenience function for quick logging
_default_logger: Optional[IncidentLogger] = None


def get_logger(db_path: Optional[str] = None) -> IncidentLogger:
    """Get or create default incident logger"""
    global _default_logger

    if _default_logger is None or (db_path and db_path != _default_logger.db_path):
        _default_logger = IncidentLogger(db_path)

    return _default_logger


def log_detection(
    input_text: str,
    result: Dict,
    **metadata
) -> int:
    """
    Quick function to log a detection result.

    Args:
        input_text: Input that was analyzed
        result: Detection result from SQLInjectionEnsemble.detect()
        **metadata: Additional context (source_ip, endpoint, etc.)

    Returns:
        Incident ID
    """
    logger = get_logger()
    return logger.log_incident(input_text, result, **metadata)


if __name__ == "__main__":
    # Demo usage
    print("SQL Injection Incident Logger - Demo")
    print("=" * 50)

    # Create logger
    logger = IncidentLogger("demo_incidents.db")

    # Simulate some incidents
    test_incidents = [
        {
            "input": "john_doe",
            "result": {
                "decision": "SAFE",
                "action": "ALLOW",
                "score": 0.12,
                "P_rf": 0.08,
                "P_cnn": 0.15,
                "semantic_score": 0,
                "confidence_level": "HIGH",
                "reason": "Low ML scores, no SQL patterns"
            }
        },
        {
            "input": "' OR '1'='1",
            "result": {
                "decision": "INJECTION",
                "action": "BLOCK",
                "score": 0.95,
                "P_rf": 0.92,
                "P_cnn": 0.97,
                "semantic_score": 8.5,
                "confidence_level": "CRITICAL",
                "reason": "High ensemble score with SQL patterns"
            }
        },
        {
            "input": "'1'1'1'1'11",
            "result": {
                "decision": "INVALID",
                "action": "LOG",
                "score": 0.72,
                "P_rf": 0.35,
                "P_cnn": 0.85,
                "semantic_score": 0.5,
                "confidence_level": "MEDIUM",
                "reason": "Model divergence, no SQL semantics"
            }
        }
    ]

    # Log incidents
    for inc in test_incidents:
        incident_id = logger.log_incident(
            inc["input"],
            inc["result"],
            source_ip="192.168.1.100",
            endpoint="/api/login",
            field_name="username"
        )
        print(f"Logged: {inc['input'][:30]}... -> ID {incident_id}")

    # Get statistics
    print("\nStatistics:")
    stats = logger.get_statistics()
    print(f"  Total incidents: {stats['total_incidents']}")
    print(f"  Blocked: {stats['blocked_count']}")
    print(f"  Block rate: {stats['block_rate']}%")

    # Query recent blocks
    print("\nRecent BLOCK incidents:")
    blocks = logger.get_incidents(action="BLOCK", limit=5)
    for b in blocks:
        print(f"  [{b['timestamp']}] {b['input_text'][:40]}...")

    # Cleanup demo file
    import os
    os.remove("demo_incidents.db")
    print("\nDemo complete!")
