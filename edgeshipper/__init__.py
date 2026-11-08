"""
edgeshipper: Zero-dependency edge log streaming daemon with store-and-forward spooling.

Modules:
  - models: RFC 5424 / RFC 3164 syslog protocol formatting and data schemas.
  - sanitizer: CWE-117 log injection and ANSI escape sequence scrubbing.
  - spooler: Crash-resilient local disk FIFO queue with backpressure protection.
  - transport: Resilient TCP/UDP network transport with keepalives and backoff.
  - tailer: POSIX inode-aware file tailer with rotation detection and stdin streaming.
  - shipper: Core daemon coordinator.
  - cli: Command-line interface.
"""

__version__ = "1.0.0"
__author__ = "Ethan Kilmer"

from edgeshipper.models import LogMessage, ShipperConfig, SpoolEntry, parse_facility, parse_severity
from edgeshipper.sanitizer import LogSanitizer, sanitize_log_message
from edgeshipper.shipper import EdgeShipper
from edgeshipper.spooler import SpoolQueue
from edgeshipper.tailer import FileTailer, StdinTailer
from edgeshipper.transport import SyslogTransport

__all__ = [
    "LogMessage",
    "ShipperConfig",
    "SpoolEntry",
    "parse_facility",
    "parse_severity",
    "LogSanitizer",
    "sanitize_log_message",
    "SpoolQueue",
    "SyslogTransport",
    "FileTailer",
    "StdinTailer",
    "EdgeShipper",
]
