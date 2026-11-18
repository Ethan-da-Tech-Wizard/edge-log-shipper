# Program: edge-log-shipper - models.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Holds the data classes (LogMessage, SpoolEntry, ShipperConfig) and the syslog facility/severity tables and RFC 5424 / RFC 3164 formatting used on the wire.
"""
Data models, schema definitions, and syslog RFC protocol encoders for edge-log-shipper.

This module provides data models for representing log messages, serialization formats,
and transport configurations. It implements formatting standards according to:
  - RFC 5424 (The Syslog Protocol - Modern Structured Format)
  - RFC 3164 (The BSD Syslog Protocol - Legacy Traditional Format)
  - RFC 6587 / RFC 5425 (Transmission of Syslog Messages over TCP, Octet-Counting Framing)

Zero external dependencies: Built strictly with Python 3 standard library modules.
"""

from __future__ import annotations

# Standard-library imports only (no third-party packages).
import datetime
import json
import os
import socket
import time
# dataclass auto-generates __init__ for the simple record classes below.
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional, Union

# ==============================================================================
# RFC 5424 / RFC 3164 SYSLOG FACILITY CODES
# Facilities categorize the system subsystem that originated the log event.
# Numerical code mapping adheres strictly to RFC 5424 Section 6.2.1.
# ==============================================================================
FACILITY_MAP: Dict[str, int] = {
    "kern": 0,       # Kernel messages
    "user": 1,       # User-level messages (default for applications)
    "mail": 2,       # Mail system
    "daemon": 3,     # System daemons
    "auth": 4,       # Security/authorization messages
    "syslog": 5,     # Messages generated internally by syslogd
    "lpr": 6,        # Line printer subsystem
    "news": 7,       # Network news subsystem
    "uucp": 8,       # UUCP subsystem
    "cron": 9,       # Clock daemon
    "authpriv": 10,  # Security/authorization messages (private)
    "ftp": 11,       # FTP daemon
    "ntp": 12,       # NTP subsystem
    "security": 13,  # Log audit / security
    "console": 14,   # Log alert / console
    "solaris-cron": 15, # Scheduling daemon
    "local0": 16,    # Locally defined facility 0 (custom apps)
    "local1": 17,    # Locally defined facility 1
    "local2": 18,    # Locally defined facility 2
    "local3": 19,    # Locally defined facility 3
    "local4": 20,    # Locally defined facility 4
    "local5": 21,    # Locally defined facility 5
    "local6": 22,    # Locally defined facility 6
    "local7": 23,    # Locally defined facility 7 (commonly edge/routers)
}

# Reverse facility mapping for human-readable introspection
# Flip name->number into number->name with a dictionary comprehension.
FACILITY_REVERSE_MAP: Dict[int, str] = {v: k for k, v in FACILITY_MAP.items()}

# ==============================================================================
# RFC 5424 / RFC 3164 SYSLOG SEVERITY CODES
# Severities describe the urgency and impact level of the logged condition.
# Numerical code mapping adheres strictly to RFC 5424 Section 6.2.1.
# ==============================================================================
SEVERITY_MAP: Dict[str, int] = {
    "emerg": 0,    # System is unusable (panic)
    "emergency": 0,
    "alert": 1,    # Action must be taken immediately
    "crit": 2,     # Critical conditions
    "critical": 2,
    "err": 3,      # Error conditions
    "error": 3,
    "warning": 4,  # Warning conditions
    "warn": 4,
    "notice": 5,   # Normal but significant condition
    "info": 6,     # Informational messages
    "informational": 6,
    "debug": 7,    # Debug-level messages
}

# Reverse severity mapping
SEVERITY_REVERSE_MAP: Dict[int, str] = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


def parse_facility(val: Union[str, int]) -> int:
    """
    Parse a facility string or integer into its RFC 5424 integer representation.

    Parameters:
        val: Facility name (e.g. 'local0', 'daemon') or integer code (0..23).

    Returns:
        Integer facility code in range [0, 23].

    Raises:
        ValueError: If facility name or number is unrecognized/out-of-bounds.
    """
    # Case 1: the caller already gave a number, so only check its range.
    if isinstance(val, int):
        if 0 <= val <= 23:
            return val
        raise ValueError(f"Syslog facility code {val} out of bounds (must be 0-23)")
    # Normalize text input: drop spaces and ignore upper/lower case.
    norm = str(val).strip().lower()
    # Case 2: a numeric string such as '16'; convert and range-check it.
    if norm.isdigit():
        code = int(norm)
        if 0 <= code <= 23:
            return code
        raise ValueError(f"Syslog facility code {code} out of bounds (must be 0-23)")
    # Case 3: a facility name such as 'local0'; look it up in the table.
    if norm in FACILITY_MAP:
        return FACILITY_MAP[norm]
    raise ValueError(f"Unknown syslog facility name '{val}'. Valid: {list(FACILITY_MAP.keys())}")


def parse_severity(val: Union[str, int]) -> int:
    """
    Parse a severity string or integer into its RFC 5424 integer representation.

    Parameters:
        val: Severity name (e.g. 'err', 'warning', 'info') or integer code (0..7).

    Returns:
        Integer severity code in range [0, 7].

    Raises:
        ValueError: If severity name or number is unrecognized/out-of-bounds.
    """
    if isinstance(val, int):
        if 0 <= val <= 7:
            return val
        raise ValueError(f"Syslog severity code {val} out of bounds (must be 0-7)")
    norm = str(val).strip().lower()
    if norm.isdigit():
        code = int(norm)
        if 0 <= code <= 7:
            return code
        raise ValueError(f"Syslog severity code {code} out of bounds (must be 0-7)")
    # Case 3: a severity name such as 'err'; look it up in the table.
    if norm in SEVERITY_MAP:
        return SEVERITY_MAP[norm]
    raise ValueError(f"Unknown syslog severity name '{val}'. Valid: {list(SEVERITY_MAP.keys())}")


@dataclass
class LogMessage:
    """
    Represents an atomic, structured log record ready for formatting and transmission.

    Attributes:
        message: The actual textual body of the log message.
        facility: Syslog facility integer (0-23). Defaults to 1 (user).
        severity: Syslog severity integer (0-7). Defaults to 6 (info).
        timestamp: Unix epoch timestamp in seconds. Defaults to current time.
        hostname: FQDN or short hostname of the emitting node. Defaults to system hostname.
        app_name: Program or component emitting the record. Defaults to 'edgeshipper'.
        procid: Process ID emitting the log. Defaults to current PID.
        msgid: Protocol message identifier (e.g. event type). Defaults to NILVALUE ('-').
        structured_data: RFC 5424 structured data string. Defaults to NILVALUE ('-').
    """
    message: str
    facility: int = 1
    severity: int = 6
    timestamp: Optional[float] = None
    hostname: Optional[str] = None
    app_name: str = "edgeshipper"
    procid: Optional[str] = None
    msgid: str = "-"
    structured_data: str = "-"

    def __post_init__(self) -> None:
        """
        Fill in default dynamic environment values if left unpopulated.
        Ensures timestamps and host identities are deterministically initialized.
        """
        # Fill in any value the caller left as None (time, hostname, process id).
        if self.timestamp is None:
            self.timestamp = time.time()
        if self.hostname is None:
            try:
                self.hostname = socket.gethostname()
            except Exception:
                self.hostname = "localhost"
        if self.procid is None:
            self.procid = str(os.getpid())

    def calculate_pri(self) -> int:
        """
        Calculate the Syslog Priority value (PRI).
        Per RFC 5424 Section 6.2.1:
            PRI = (Facility * 8) + Severity
        
        Example:
            Facility 1 (user) * 8 + Severity 6 (info) = 8 + 6 = 14.
            Enclosed in wire format as: <14>
        """
        # Facility goes in the upper bits (x8) and severity in the lower 3 bits.
        return (self.facility * 8) + self.severity

    def format_rfc5424(self) -> str:
        """
        Encode the message according to modern RFC 5424 syslog specification.

        Wire format structure:
            <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

        Components:
            - PRI: Calculated priority enclosed in angle brackets.
            - VERSION: Syslog protocol version ('1' for RFC 5424).
            - TIMESTAMP: ISO-8601 / RFC 3339 formatted UTC timestamp with microsecond
                         resolution (e.g., 2026-11-08T07:45:00.123456Z).
            - HOSTNAME: Identifier for the originating machine (max 255 chars).
            - APP-NAME: Identifier for application or agent (max 48 chars).
            - PROCID: Process identification string (e.g., PID or container ID).
            - MSGID: Classification of message (e.g. ID47 or NILVALUE '-').
            - STRUCTURED-DATA: Bracketed structured fields or NILVALUE '-'.
            - MSG: The payload message content.
        """
        # Compute the <PRI> number that starts every syslog line.
        pri = self.calculate_pri()
        version = "1"

        # Format timestamp to ISO 8601 UTC with microsecond precision:
        # Example: 2026-11-08T07:45:00.123456+00:00 or with trailing Z
        dt = datetime.datetime.fromtimestamp(self.timestamp or time.time(), tz=datetime.timezone.utc)
        iso_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Sanitize metadata fields to avoid whitespace delimiters breaking RFC parser
        host = (self.hostname or "-").replace(" ", "_")[:255]
        app = (self.app_name or "-").replace(" ", "_")[:48]
        pid = (self.procid or "-").replace(" ", "_")[:128]
        mid = (self.msgid or "-").replace(" ", "_")[:32]
        sd = self.structured_data if self.structured_data else "-"

        # Assemble RFC 5424 header and payload
        header = f"<{pri}>{version} {iso_ts} {host} {app} {pid} {mid} {sd}"
        # Only append the message text if there is one; otherwise send just the header.
        if self.message:
            return f"{header} {self.message}"
        return header

    def format_rfc3164(self) -> str:
        """
        Encode the message according to legacy RFC 3164 (BSD syslog) specification.

        Wire format structure:
            <PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG

        Notice that RFC 3164 BSD timestamp requires space-padded single-digit days
        (e.g. 'Oct  5' instead of 'Oct 05') and lacks timezone offsets.
        """
        pri = self.calculate_pri()
        dt = datetime.datetime.fromtimestamp(self.timestamp or time.time())
        
        # Format BSD style date: 'Mmm dd hh:mm:ss' with space-padding for days < 10
        month_abbr = dt.strftime("%b")
        day_str = f"{dt.day:2d}" # 2-character space-padded day
        time_str = dt.strftime("%H:%M:%S")
        bsd_ts = f"{month_abbr} {day_str} {time_str}"

        host = (self.hostname or "localhost").replace(" ", "_")
        app = (self.app_name or "edgeshipper").replace(" ", "_")
        pid_suffix = f"[{self.procid}]" if self.procid else ""

        return f"<{pri}>{bsd_ts} {host} {app}{pid_suffix}: {self.message}"

    def to_wire_bytes(self, format_type: str = "rfc5424", framing: str = "octet") -> bytes:
        """
        Serialize log record to raw bytes ready for socket transmission.

        Parameters:
            format_type: 'rfc5424' (modern) or 'rfc3164' (legacy BSD).
            framing:
                - 'octet': RFC 6587 Octet Counting. Prepends byte count and space.
                           Example: b"124 <14>1 2026-11-08T... msg"
                           Ensures robust stream boundary detection across TCP buffers.
                - 'newline': Non-transparent framing appending trailing newline (\\n).
                           Example: b"<14>1 2026-11-08T... msg\\n"

        Returns:
            Encoded bytes formatted according to the requested standard.
        """
        if format_type.lower() == "rfc3164":
            text = self.format_rfc3164()
        else:
            text = self.format_rfc5424()

        # Convert text to bytes; bad characters become replacement marks instead of crashing.
        payload_bytes = text.encode("utf-8", errors="replace")

        # Octet framing: tell the receiver exactly how many bytes follow.
        if framing.lower() == "octet":
            # RFC 6587 Section 3.4.1: Octet Counting
            # Structure: MSG-LEN SP MSG
            # MSG-LEN is the exact length of the message payload in octets (bytes)
            length_prefix = f"{len(payload_bytes)} ".encode("ascii")
            return length_prefix + payload_bytes
        else:
            # Non-transparent framing with newline delimiter
            if not payload_bytes.endswith(b"\n"):
                return payload_bytes + b"\n"
            return payload_bytes

    def to_dict(self) -> Dict[str, Any]:
        """Convert log record to dictionary for local JSON spooling serialization."""
        # asdict turns the dataclass into a plain dictionary that json can save.
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LogMessage:
        """Hydrate a LogMessage instance from serialized dictionary."""
        return cls(
            message=data.get("message", ""),
            facility=data.get("facility", 1),
            severity=data.get("severity", 6),
            timestamp=data.get("timestamp"),
            hostname=data.get("hostname"),
            app_name=data.get("app_name", "edgeshipper"),
            procid=data.get("procid"),
            msgid=data.get("msgid", "-"),
            structured_data=data.get("structured_data", "-"),
        )


@dataclass
class SpoolEntry:
    """
    Represents a queued log entry persisted on disk in the store-and-forward spooler.

    Attributes:
        id: Unique identifier for tracking and atomic queue acknowledgment.
        created_at: Epoch timestamp when the entry entered the spool queue.
        log_message: The encapsulated LogMessage object.
        attempts: Number of unsuccessful transmission attempts.
    """
    id: str
    created_at: float
    # The wrapped log record (stored as a nested dictionary in JSON).
    log_message: LogMessage
    attempts: int = 0

    def to_json(self) -> str:
        """Serialize spool record to compact JSON string."""
        # Build one JSON object per queue entry (one line in the journal file).
        return json.dumps({
            "id": self.id,
            "created_at": self.created_at,
            "attempts": self.attempts,
            "log_message": self.log_message.to_dict(),
        })

    @classmethod
    def from_json(cls, json_str: str) -> SpoolEntry:
        """Parse serialized JSON string into a SpoolEntry."""
        data = json.loads(json_str)
        return cls(
            id=data["id"],
            created_at=data["created_at"],
            attempts=data.get("attempts", 0),
            log_message=LogMessage.from_dict(data["log_message"]),
        )


@dataclass
class ShipperConfig:
    """
    Global operational configuration for the edge log shipping daemon.

    Attributes:
        target_host: Upstream syslog receiver IP or hostname (e.g. WireGuard mesh node).
        target_port: Upstream destination port (default 514 for syslog).
        protocol: Transport layer protocol ('tcp' or 'udp').
        syslog_format: Syslog encoding specification ('rfc5424' or 'rfc3164').
        framing: Stream boundary framing for TCP ('octet' or 'newline').
        spool_dir: Local filesystem directory for storing store-and-forward spool buffer.
        max_spool_bytes: Hard upper limit on disk consumption for the spool queue.
        max_spool_entries: Maximum number of backlog messages retained in spool.
        connect_timeout: Network socket connection timeout in seconds.
        send_timeout: Network socket write timeout in seconds.
        reconnect_backoff_initial: Starting backoff delay in seconds upon disconnect.
        reconnect_backoff_max: Maximum backoff delay ceiling in seconds.
        reconnect_backoff_multiplier: Geometric multiplier for exponential backoff.
        sanitize: Whether to scrub log injection attacks (CWE-117) and ANSI escapes.
        app_name: Default app-name identifier embedded in syslog headers.
        facility: Default syslog facility code (0..23).
        severity: Default syslog severity code (0..7).
    """
    target_host: str = "127.0.0.1"
    target_port: int = 514
    protocol: str = "tcp"
    syslog_format: str = "rfc5424"
    framing: str = "octet"
    spool_dir: str = "/tmp/edgeshipper_spool"
    max_spool_bytes: int = 50 * 1024 * 1024  # 50 MB disk cap
    max_spool_entries: int = 100_000
    connect_timeout: float = 3.0
    send_timeout: float = 5.0
    reconnect_backoff_initial: float = 1.0
    reconnect_backoff_max: float = 30.0
    reconnect_backoff_multiplier: float = 2.0
    sanitize: bool = True
    app_name: str = "edgeshipper"
    facility: int = 1
    severity: int = 6

    def __post_init__(self) -> None:
        """Validate protocol and framing options upon instantiation."""
        # Normalize each option to lower case, then reject unsupported values with a clear error.
        self.protocol = self.protocol.lower()
        if self.protocol not in ("tcp", "udp"):
            raise ValueError(f"Unsupported transport protocol '{self.protocol}'. Must be 'tcp' or 'udp'.")

        self.syslog_format = self.syslog_format.lower()
        if self.syslog_format not in ("rfc5424", "rfc3164"):
            raise ValueError(f"Unsupported syslog format '{self.syslog_format}'. Must be 'rfc5424' or 'rfc3164'.")

        self.framing = self.framing.lower()
        if self.framing not in ("octet", "newline"):
            raise ValueError(f"Unsupported stream framing '{self.framing}'. Must be 'octet' or 'newline'.")
