# ==============================================================================
# Program: shipper.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Core edge log shipper orchestration daemon coordinating the sanitizer,
#          RFC protocol formatter, disk spool queue, and network socket transport.
# ==============================================================================
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

# Stdlib only. The core pipeline below uses logging, time and typing helpers
# plus our own modules; signal handling lives in the CLI, not here.
import logging
import time
from typing import Any, Dict, Iterator, List, Optional, Union

from edgeshipper.models import LogMessage, ShipperConfig, SpoolEntry
from edgeshipper.sanitizer import LogSanitizer
from edgeshipper.spooler import SpoolQueue
from edgeshipper.tailer import FileTailer, StdinTailer
from edgeshipper.transport import SyslogTransport

# Library-style logger: no handlers are attached here, so the host
# application decides where (or whether) diagnostics are emitted.
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
        self.config = config or ShipperConfig()
        # None (rather than a no-op sanitizer) lets ship_message skip the work
        # entirely when the operator passed --no-sanitize.
        self.sanitizer = LogSanitizer() if self.config.sanitize else None
        # The spooler is created eagerly so a backlog left by a previous run
        # (crash, reboot) is visible to the FIFO check immediately.
        self.spooler = SpoolQueue(
            spool_dir=self.config.spool_dir,
            max_spool_bytes=self.config.max_spool_bytes,
            max_spool_entries=self.config.max_spool_entries,
        )
        # Constructing the transport does not connect; the socket is opened lazily
        # on first send so startup never blocks on an unreachable collector.
        self.transport = SyslogTransport(self.config)
        # Cooperative stop flag checked by run_stream between lines.
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
        log_entry = LogMessage(
            message=msg_text,
            facility=facility if facility is not None else self.config.facility,
            severity=severity if severity is not None else self.config.severity,
            # Capture the event time here, before any spooling delay, so a replayed
            # record carries its original time rather than the time it was delivered.
            timestamp=timestamp or time.time(),
            app_name=app_name or self.config.app_name,
        )

        # Step 3: Check FIFO ordering constraint
        # If older records are already queued in the spool buffer, this new record MUST
        # be appended to the spool queue first to prevent timeline inversion.
        # Presence of ANY backlog diverts new records into the spool; this is what
        # keeps delivery order identical to arrival order after an outage.
        spool_status = self.spooler.status()
        if spool_status["pending_count"] > 0:
            self.spooler.enqueue(log_entry)
            # Attempt opportunistic drain of backlog
            # Opportunistic, bounded drain so a recovered link catches up gradually
            # while the stream keeps flowing; a failure here simply leaves records
            # queued for the next attempt.
            self.flush_spool(batch_size=50)
            return True

        # Step 4: Spool is empty: Attempt direct socket transmission
        wire_bytes = log_entry.to_wire_bytes(
            format_type=self.config.syslog_format,
            framing=self.config.framing,
        )

        # send_bytes returns False on failure (it makes one reconnect attempt itself
        # and swallows socket errors rather than raising), which triggers the spool fallback below.
        sent = self.transport.send_bytes(wire_bytes)
        if sent:
            return True

        # Step 5: Socket send failed: Buffer into store-and-forward spooler
        # Returning True here means 'accepted for delivery' (spooled), not
        # 'delivered'; callers can inspect the spooler status to tell the two apart.
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
        # peek reads without removing: records are only deleted via acknowledge()
        # AFTER a successful send, giving at-least-once delivery across crashes.
        entries = self.spooler.peek(limit=batch_size)
        if not entries:
            return 0

        # Attempt to ensure transport connection is active
        # Probe the connection once up front so an unreachable collector costs a
        # single failed connect per flush instead of one per spooled record.
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
                # Everything from the failing record onward is still pending; bump their
                # attempt counters and stop so order is preserved (no skipping ahead).
                failed_ids = [e.id for e in entries[successfully_sent:]]
                self.spooler.increment_attempts(failed_ids)
                break

        # Atomically acknowledge and remove all delivered entries from disk
        if successfully_sent > 0:
            # Acknowledge a count, not ids: delivery is strictly head-first, so the
            # first N spooled entries are exactly the ones just sent.
            self.spooler.acknowledge(successfully_sent)

        return successfully_sent

    def run_stream(self, line_iterator: Iterator[str]) -> None:
        """
        Continuously stream lines from an iterator (FileTailer or StdinTailer).

        Parameters:
            line_iterator: Generator yielding individual log lines.
        """
        self._is_running = True
        # Throttle for the periodic backlog drain below, so we do not stat the
        # spool directory on every single line of a busy stream.
        last_flush_check = time.time()

        try:
            for line in line_iterator:
                if not self._is_running:
                    break

                self.ship_message(line)

                # Periodic background spool flush check every 2 seconds
                now = time.time()
                if now - last_flush_check > 2.0:
                    last_flush_check = now
                    spool_stat = self.spooler.status()
                    if spool_stat["pending_count"] > 0:
                        self.flush_spool(batch_size=100)

        # Always run close() so the last spooled records get a final flush and the
        # socket is released, even when the iterator raises.
        finally:
            self.close()

    def close(self) -> None:
        """Cleanly stop the shipper and close transport resources."""
        # Clear first so a concurrent run_stream loop stops accepting more lines.
        self._is_running = False
        # Attempt a final flush of any remaining pending records
        try:
            self.flush_spool(batch_size=200)
        # Shutdown is best-effort: an unreachable collector must not prevent the
        # socket from being closed. Unsent records stay safely on disk.
        except Exception:
            pass
        self.transport.close()
