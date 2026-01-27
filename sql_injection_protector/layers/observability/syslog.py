"""Syslog exporter for sending events to SIEM systems."""

import asyncio
import logging
import socket
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)


class SyslogFacility(IntEnum):
    """Syslog facility codes."""

    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(IntEnum):
    """Syslog severity codes."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


@dataclass
class SyslogMessage:
    """A syslog message."""

    message: str
    facility: SyslogFacility = SyslogFacility.LOCAL0
    severity: SyslogSeverity = SyslogSeverity.INFO
    hostname: Optional[str] = None
    app_name: str = "sqli-protector"
    procid: Optional[str] = None
    msgid: Optional[str] = None
    timestamp: Optional[datetime] = None

    def format_rfc3164(self) -> bytes:
        """
        Format as RFC 3164 (BSD syslog).

        Format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        """
        pri = (self.facility.value * 8) + self.severity.value
        timestamp = (self.timestamp or datetime.utcnow()).strftime("%b %d %H:%M:%S")
        hostname = self.hostname or socket.gethostname()

        msg = f"<{pri}>{timestamp} {hostname} {self.app_name}: {self.message}"
        return msg.encode("utf-8")

    def format_rfc5424(self) -> bytes:
        """
        Format as RFC 5424 (modern syslog).

        Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
        """
        pri = (self.facility.value * 8) + self.severity.value
        version = 1
        timestamp = (self.timestamp or datetime.utcnow()).isoformat() + "Z"
        hostname = self.hostname or socket.gethostname()
        procid = self.procid or "-"
        msgid = self.msgid or "-"
        structured_data = "-"  # No structured data for now

        msg = f"<{pri}>{version} {timestamp} {hostname} {self.app_name} {procid} {msgid} {structured_data} {self.message}"
        return msg.encode("utf-8")


class SyslogExporter:
    """
    Syslog exporter for sending events to SIEM systems.

    Supports:
    - UDP transport (default, fire-and-forget)
    - TCP transport (reliable, with reconnection)
    - RFC 3164 and RFC 5424 formats
    """

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
        facility: SyslogFacility = SyslogFacility.LOCAL0,
        use_rfc5424: bool = True,
        app_name: str = "sqli-protector",
        hostname: Optional[str] = None,
    ):
        """
        Initialize syslog exporter.

        Args:
            host: Syslog server hostname or IP
            port: Syslog server port
            protocol: 'udp' or 'tcp'
            facility: Syslog facility
            use_rfc5424: Use RFC 5424 format (vs RFC 3164)
            app_name: Application name
            hostname: Hostname to report (default: auto-detect)
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.facility = facility
        self.use_rfc5424 = use_rfc5424
        self.app_name = app_name
        self.hostname = hostname or socket.gethostname()

        self._socket: Optional[socket.socket] = None
        self._connected = False
        self._send_count = 0
        self._error_count = 0

    async def connect(self) -> bool:
        """
        Establish connection (TCP) or create socket (UDP).

        Returns:
            True if successful
        """
        try:
            if self.protocol == "tcp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(10)
                self._socket.connect((self.host, self.port))
                self._connected = True
                logger.info(f"Connected to syslog server {self.host}:{self.port} (TCP)")
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._connected = True
                logger.info(f"Created UDP socket for syslog {self.host}:{self.port}")

            return True

        except Exception as e:
            logger.error(f"Failed to connect to syslog: {e}")
            self._error_count += 1
            return False

    async def disconnect(self) -> None:
        """Close the connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
            self._connected = False
            logger.info("Disconnected from syslog server")

    async def send(
        self,
        message: str,
        severity: SyslogSeverity = SyslogSeverity.INFO,
        msgid: Optional[str] = None,
    ) -> bool:
        """
        Send a message to syslog.

        Args:
            message: Message content
            severity: Syslog severity
            msgid: Message ID for RFC 5424

        Returns:
            True if sent successfully
        """
        if not self._connected:
            if not await self.connect():
                return False

        syslog_msg = SyslogMessage(
            message=message,
            facility=self.facility,
            severity=severity,
            hostname=self.hostname,
            app_name=self.app_name,
            msgid=msgid,
        )

        if self.use_rfc5424:
            data = syslog_msg.format_rfc5424()
        else:
            data = syslog_msg.format_rfc3164()

        try:
            if self.protocol == "tcp":
                # TCP needs newline terminator
                self._socket.send(data + b"\n")
            else:
                # UDP send
                self._socket.sendto(data, (self.host, self.port))

            self._send_count += 1
            return True

        except Exception as e:
            logger.error(f"Failed to send syslog message: {e}")
            self._error_count += 1
            self._connected = False
            return False

    async def send_cef(self, cef_message: str) -> bool:
        """
        Send a CEF-formatted message to syslog.

        Args:
            cef_message: CEF formatted string

        Returns:
            True if sent successfully
        """
        return await self.send(
            cef_message,
            severity=SyslogSeverity.NOTICE,
            msgid="cef",
        )

    async def send_alert(self, message: str) -> bool:
        """Send an alert-level message."""
        return await self.send(message, severity=SyslogSeverity.ALERT, msgid="alert")

    async def send_warning(self, message: str) -> bool:
        """Send a warning-level message."""
        return await self.send(message, severity=SyslogSeverity.WARNING, msgid="warn")

    async def send_error(self, message: str) -> bool:
        """Send an error-level message."""
        return await self.send(message, severity=SyslogSeverity.ERROR, msgid="error")

    def get_stats(self) -> dict:
        """Get exporter statistics."""
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "connected": self._connected,
            "messages_sent": self._send_count,
            "errors": self._error_count,
        }

    @property
    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connected


class AsyncSyslogExporter(SyslogExporter):
    """Async syslog exporter using asyncio for non-blocking I/O."""

    async def connect(self) -> bool:
        """Establish async connection."""
        try:
            if self.protocol == "tcp":
                reader, writer = await asyncio.open_connection(
                    self.host, self.port
                )
                self._reader = reader
                self._writer = writer
                self._connected = True
                logger.info(f"Async connected to syslog {self.host}:{self.port}")
            else:
                # UDP remains synchronous
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setblocking(False)
                self._connected = True

            return True

        except Exception as e:
            logger.error(f"Async connection failed: {e}")
            self._error_count += 1
            return False

    async def send(
        self,
        message: str,
        severity: SyslogSeverity = SyslogSeverity.INFO,
        msgid: Optional[str] = None,
    ) -> bool:
        """Send message asynchronously."""
        if not self._connected:
            if not await self.connect():
                return False

        syslog_msg = SyslogMessage(
            message=message,
            facility=self.facility,
            severity=severity,
            hostname=self.hostname,
            app_name=self.app_name,
            msgid=msgid,
        )

        if self.use_rfc5424:
            data = syslog_msg.format_rfc5424()
        else:
            data = syslog_msg.format_rfc3164()

        try:
            if self.protocol == "tcp" and hasattr(self, "_writer"):
                self._writer.write(data + b"\n")
                await self._writer.drain()
            else:
                # UDP
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: self._socket.sendto(data, (self.host, self.port))
                )

            self._send_count += 1
            return True

        except Exception as e:
            logger.error(f"Async send failed: {e}")
            self._error_count += 1
            self._connected = False
            return False
