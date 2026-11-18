# Program: edge-log-shipper - shipper.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Defines EdgeShipper, which sanitizes, formats and sends log lines over the network, falling back to the disk spool and replaying it in order.
"""
Core Edge Log Shipper Orchestration Daemon.

================================================================================
ARCHITECTURE & ORDERING INVARIANTS:
================================================================================
The Shipper coordinates four decoupled subsystems:
  1. Sanitizer: Defensive scrubbing of CWE-117 log injection and ANSI attacks.
  2. Formatter: RFC 5424 / RFC 3164 syslog protocol wire encoding.
  3. Spooler: Crash-resilient local disk FIFO queue (store-and-forward).
  4. Transport: Non-blocking TCP/UDP socket with keepalives and backoff retry.

FIFO Ordering Invariant:
A critical bug in poorly designed log forwarders is out-of-order log delivery during
network recovery. If the shipper attempts to transmit a new incoming log directly
while older logs remain queued in the local spool, forensic timeline ordering is broken!
The Shipper enforces strict causal FIFO ordering:
  - If the spool queue is non-empty, ALL incoming logs are first enqueued to the spool.
  - The shipper attempts to drain the head of the spool first.
  - Only when the spool is completely drained (0 pending) will new logs bypass the spool
    and transmit directly over the active socket.
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from typing import Any, Dict, Iterator, List, Optional, Union

from edgeshipper.models import LogMessage, ShipperConfig, SpoolEntry
from edgeshipper.sanitizer import LogSanitizer
from edgeshipper.spooler import SpoolQueue
from edgeshipper.tailer import FileTailer, StdinTailer
from edgeshipper.transport import SyslogTransport

# Module-level logger named after the package.
logger = logging.getLogger("edgeshipper")


class EdgeShipper:
    """
    Primary coordinator engine running the edge log shipping and spooling pipeline.
    """

    def __init__(self, config: Optional[ShipperConfig] = None) -> None:
        """
        Initialize the EdgeShipper daemon.

        Parameters:
            config: Operational configuration settings. Uses defaults if omitted.
        """
        # Use the given settings, or the defaults if none were provided.
        self.config = config or ShipperConfig()
        # Only create a sanitizer when sanitizing is switched on.
        self.sanitizer = LogSanitizer() if self.config.sanitize else None
        # The disk queue that holds messages while the network is unavailable.
        self.spooler = SpoolQueue(
            spool_dir=self.config.spool_dir,
            max_spool_bytes=self.config.max_spool_bytes,
            max_spool_entries=self.config.max_spool_entries,
        )
        # The network client that actually sends bytes to the collector.
        self.transport = SyslogTransport(self.config)
        # Flag checked by run_stream so the loop can be stopped.
        self._is_running: bool = False

    def ship_message(
        self,
        raw_message: str,
        facility: Optional[int] = None,
        severity: Optional[int] = None,
        app_name: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> bool:
        """
        Process and ship a single log message.

        Enforces sanitization, FIFO spool ordering, and automatic failover to disk buffer.

        Parameters:
            raw_message: Raw string payload from log stream or application.
            facility: Optional syslog facility override (0..23).
            severity: Optional syslog severity override (0..7).
            app_name: Optional application name override.
            timestamp: Optional timestamp override.

        Returns:
            True if delivered immediately or queued to spool; False if dropped on catastrophic failure.
        """
        # Step 1: CWE-117 Defensive Sanitization
        msg_text = raw_message
        if self.sanitizer is not None:
            msg_text = self.sanitizer.sanitize(raw_message)

        # Step 2: Construct LogMessage record
        # Use the caller's override if given, otherwise fall back to the configured default (same pattern for each field).
        log_entry = LogMessage(
            message=msg_text,
            facility=facility if facility is not None else self.config.facility,
            severity=severity if severity is not None else self.config.severity,
            timestamp=timestamp or time.time(),
            app_name=app_name or self.config.app_name,
        )

        # Step 3: Check FIFO ordering constraint
        # If older records are already queued in the spool buffer, this new record MUST
        # be appended to the spool queue first to prevent timeline inversion.
        # Ask the spool how many messages are waiting.
        spool_status = self.spooler.status()
        if spool_status["pending_count"] > 0:
            self.spooler.enqueue(log_entry)
            # Attempt opportunistic drain of backlog
            # Try to send some of the backlog right away, oldest first.
            self.flush_spool(batch_size=50)
            return True

        # Step 4: Spool is empty: Attempt direct socket transmission
        # Turn the record into the exact bytes that go on the network.
        wire_bytes = log_entry.to_wire_bytes(
            format_type=self.config.syslog_format,
            framing=self.config.framing,
        )

        # True means the collector accepted the bytes.
        sent = self.transport.send_bytes(wire_bytes)
        if sent:
            return True

        # Step 5: Socket send failed: Buffer into store-and-forward spooler
        self.spooler.enqueue(log_entry)
        return True

    def flush_spool(self, batch_size: int = 100) -> int:
        """
        Drain pending records from the local spool buffer and transmit upstream.

        Parameters:
            batch_size: Number of records to attempt in a single drain cycle.

        Returns:
            Count of successfully transmitted and acknowledged records.
        """
        # Look at the oldest entries without removing them yet (removal happens only after a successful send).
        entries = self.spooler.peek(limit=batch_size)
        if not entries:
            return 0

        # Attempt to ensure transport connection is active
        # Make sure there is a live connection before sending the batch.
        if not self.transport.is_connected:
            if not self.transport.connect():
                return 0

        successfully_sent = 0
        for entry in entries:
            wire_bytes = entry.log_message.to_wire_bytes(
                format_type=self.config.syslog_format,
                framing=self.config.framing,
            )
            success = self.transport.send_bytes(wire_bytes)
            if success:
                successfully_sent += 1
            else:
                # Network failed mid-batch: increment failure attempts and halt flush
                # Everything not yet sent in this batch counts as one more failed attempt.
                failed_ids = [e.id for e in entries[successfully_sent:]]
                self.spooler.increment_attempts(failed_ids)
                break

        # Atomically acknowledge and remove all delivered entries from disk
        if successfully_sent > 0:
            # Remove exactly the entries that were delivered, keeping order.
            self.spooler.acknowledge(successfully_sent)

        return successfully_sent

    def run_stream(self, line_iterator: Iterator[str]) -> None:
        """
        Continuously stream lines from an iterator (FileTailer or StdinTailer).

        Parameters:
            line_iterator: Generator yielding individual log lines.
        """
        # Mark the loop as active.
        self._is_running = True
        last_flush_check = time.time()

        try:
            # Each loop pass handles one log line from the tailer.
            for line in line_iterator:
                if not self._is_running:
                    break

                self.ship_message(line)

                # Periodic background spool flush check every 2 seconds
                now = time.time()
                # Every 2 seconds, try to drain any backlog even if new lines are arriving.
                if now - last_flush_check > 2.0:
                    last_flush_check = now
                    spool_stat = self.spooler.status()
                    if spool_stat["pending_count"] > 0:
                        self.flush_spool(batch_size=100)

        finally:
            # Always clean up, even if the stream raised an error.
            self.close()

    def close(self) -> None:
        """Cleanly stop the shipper and close transport resources."""
        self._is_running = False
        # Attempt a final flush of any remaining pending records
        try:
            # Last attempt to send whatever is still queued.
            self.flush_spool(batch_size=200)
        except Exception:
            pass
        # Release the socket.
        self.transport.close()
