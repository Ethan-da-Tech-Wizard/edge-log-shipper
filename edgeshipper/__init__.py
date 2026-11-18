# ==============================================================================
# Program: __init__.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Package entrypoint for edgeshipper, exposing core syslog data models,
#          sanitization engines, disk FIFO spool queues, and network transport clients.
# ==============================================================================
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

# Step 1: Export public API symbols for edge-log-shipper
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
