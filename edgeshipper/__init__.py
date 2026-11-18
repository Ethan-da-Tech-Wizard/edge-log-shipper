# Program: edge-log-shipper - __init__.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Package entry point that exposes the main classes and helpers of edgeshipper (the edge syslog shipper) and records the version.
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

# Version string of the package (also shown by the CLI's --version flag).
__version__ = "1.0.0"
__author__ = "Ethan Kilmer"

# Re-export the public pieces so users can write: from edgeshipper import EdgeShipper
from edgeshipper.models import LogMessage, ShipperConfig, SpoolEntry, parse_facility, parse_severity
from edgeshipper.sanitizer import LogSanitizer, sanitize_log_message
from edgeshipper.shipper import EdgeShipper
from edgeshipper.spooler import SpoolQueue
from edgeshipper.tailer import FileTailer, StdinTailer
from edgeshipper.transport import SyslogTransport

# __all__ lists the names that 'from edgeshipper import *' will expose.
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
