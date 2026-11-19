# ==============================================================================
# Program: test_edgeshipper.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Exhaustive unit and integration test suite for edge-log-shipper validating
#          RFC 5424/3164 formatting, CWE-117 sanitization, disk spool queues, and tailers.
# ==============================================================================
"""
Exhaustive Unit and Integration Test Suite for edge-log-shipper.

Validates:
  - RFC 5424 / RFC 3164 protocol serialization and PRI calculation.
  - Framing encodings (RFC 6587 octet counting and newline framing).
  - CWE-117 log injection and ANSI escape sequence scrubbing.
  - Persistent FIFO spooling, disk backpressure limits, crash recovery.
  - Resilient TCP/UDP network socket transport with mock servers.
  - POSIX inode rotation detection, file truncation, and partial line buffering.
  - Full end-to-end store-and-forward daemon workflows.
"""

from __future__ import annotations

# Only the standard library is needed: unittest as the runner, tempfile for
# isolated spool directories, threading + socket for loopback mock servers.
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# Ensure package directory is in sys.path for direct unittest discovery
# Allow running this file directly (python tests/test_edgeshipper.py) without
# installing the package: put the repo root on sys.path so 'edgeshipper' imports.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from edgeshipper.cli import build_parser, main
from edgeshipper.models import (
    FACILITY_MAP,
    SEVERITY_MAP,
    LogMessage,
    ShipperConfig,
    SpoolEntry,
    parse_facility,
    parse_severity,
)
from edgeshipper.sanitizer import LogSanitizer, sanitize_log_message
from edgeshipper.shipper import EdgeShipper
from edgeshipper.spooler import SpoolQueue
from edgeshipper.tailer import FileTailer, StdinTailer
from edgeshipper.transport import SyslogTransport


# Step 1: Test syslog protocol encoders, PRI calculations, and framing formats
class TestSyslogModels(unittest.TestCase):
    """Test suite for syslog models, parsers, and wire format serialization."""

    # Covers symbolic names, ints, numeric strings, and rejection of unknown or
    # out-of-range values (both 24 and negatives).
    def test_facility_parsing(self) -> None:
        self.assertEqual(parse_facility("kern"), 0)
        self.assertEqual(parse_facility("user"), 1)
        self.assertEqual(parse_facility("auth"), 4)
        self.assertEqual(parse_facility("local7"), 23)
        self.assertEqual(parse_facility(16), 16)
        self.assertEqual(parse_facility("16"), 16)

        with self.assertRaises(ValueError):
            parse_facility("invalid_facility")
        with self.assertRaises(ValueError):
            parse_facility(24)
        with self.assertRaises(ValueError):
            parse_facility(-1)

    # Same contract as facilities, with the 0-7 range.
    def test_severity_parsing(self) -> None:
        self.assertEqual(parse_severity("emerg"), 0)
        self.assertEqual(parse_severity("alert"), 1)
        self.assertEqual(parse_severity("crit"), 2)
        self.assertEqual(parse_severity("err"), 3)
        self.assertEqual(parse_severity("warning"), 4)
        self.assertEqual(parse_severity("notice"), 5)
        self.assertEqual(parse_severity("info"), 6)
        self.assertEqual(parse_severity("debug"), 7)
        self.assertEqual(parse_severity(3), 3)

        with self.assertRaises(ValueError):
            parse_severity("unknown_severity")
        with self.assertRaises(ValueError):
            parse_severity(8)

    # PRI arithmetic checked against hand-computed values, including both
    # boundary cases (0 and a high local facility).
    def test_pri_calculation(self) -> None:
        # PRI = (facility * 8) + severity
        # user (1) * 8 + info (6) = 14
        msg = LogMessage(message="test", facility=1, severity=6)
        self.assertEqual(msg.calculate_pri(), 14)

        # local0 (16) * 8 + err (3) = 128 + 3 = 131
        msg2 = LogMessage(message="test", facility=16, severity=3)
        self.assertEqual(msg2.calculate_pri(), 131)

        # kern (0) * 8 + emerg (0) = 0
        msg3 = LogMessage(message="test", facility=0, severity=0)
        self.assertEqual(msg3.calculate_pri(), 0)

    # Asserts structure (PRI+version prefix, fields present, message last)
    # rather than the full string, because the timestamp is rendered in UTC and
    # the hostname/PID defaults are environment-dependent.
    def test_rfc5424_formatting(self) -> None:
        ts = 1700000000.123456
        msg = LogMessage(
            message="System initialized successfully",
            facility=1,
            severity=6,
            timestamp=ts,
            hostname="edge-node-01",
            app_name="auditd",
            procid="1024",
            msgid="INIT01",
        )
        wire_str = msg.format_rfc5424()
        self.assertTrue(wire_str.startswith("<14>1 "))
        self.assertIn("edge-node-01", wire_str)
        self.assertIn("auditd", wire_str)
        self.assertIn("1024", wire_str)
        self.assertIn("INIT01", wire_str)
        self.assertTrue(wire_str.endswith("System initialized successfully"))

    # RFC 3164 timestamps use local time, so the test checks only the PRI and
    # the 'host tag[pid]: message' tail, which are timezone independent.
    def test_rfc3164_formatting(self) -> None:
        ts = 1700000000.0  # Wed Nov 14 2023
        msg = LogMessage(
            message="Kernel link up",
            facility=0,
            severity=5,
            timestamp=ts,
            hostname="firewall01",
            app_name="network",
            procid="42",
        )
        formatted = msg.format_rfc3164()
        # PRI = 0 * 8 + 5 = 5 -> <5>
        self.assertTrue(formatted.startswith("<5>"))
        self.assertIn("firewall01 network[42]: Kernel link up", formatted)

    # Octet counting: the decimal prefix must equal the payload length in bytes.
    # Newline framing: the frame must end with a line feed.
    def test_framing_encodings(self) -> None:
        msg = LogMessage(message="Ping", facility=1, severity=6)
        
        # Octet counting framing: '<length> <payload>'
        octet_bytes = msg.to_wire_bytes(format_type="rfc5424", framing="octet")
        space_idx = octet_bytes.find(b" ")
        length_str = octet_bytes[:space_idx].decode("ascii")
        payload = octet_bytes[space_idx + 1:]
        self.assertEqual(int(length_str), len(payload))

        # Newline framing: '<payload>\n'
        nl_bytes = msg.to_wire_bytes(format_type="rfc5424", framing="newline")
        self.assertTrue(nl_bytes.endswith(b"\n"))

    # Round-trip through JSON, the on-disk spool format, must preserve every
    # field the replay path depends on.
    def test_logmessage_and_spoolentry_serialization(self) -> None:
        msg = LogMessage(message="Disk alert", facility=16, severity=3)
        entry = SpoolEntry(id="entry123", created_at=time.time(), log_message=msg, attempts=1)

        json_str = entry.to_json()
        deserialized = SpoolEntry.from_json(json_str)
        self.assertEqual(deserialized.id, "entry123")
        self.assertEqual(deserialized.attempts, 1)
        self.assertEqual(deserialized.log_message.message, "Disk alert")
        self.assertEqual(deserialized.log_message.facility, 16)
        self.assertEqual(deserialized.log_message.severity, 3)

    # Bad protocol, format and framing values must fail fast at construction.
    def test_config_validation(self) -> None:
        # Valid config
        cfg = ShipperConfig(protocol="tcp", syslog_format="rfc5424", framing="octet")
        self.assertEqual(cfg.protocol, "tcp")

        # Invalid protocol
        with self.assertRaises(ValueError):
            ShipperConfig(protocol="sctp")

        # Invalid format
        with self.assertRaises(ValueError):
            ShipperConfig(syslog_format="custom_json")

        # Invalid framing
        with self.assertRaises(ValueError):
            ShipperConfig(framing="header_len")


# Step 2: Test CWE-117 sanitization, ANSI stripping, and length limits
class TestLogSanitizer(unittest.TestCase):
    """Test suite for CWE-117 log injection and ANSI terminal scrubbing."""

    def setUp(self) -> None:
        self.sanitizer = LogSanitizer()

    # Covers CSI sequences (colour, clear screen) and an OSC window-title
    # sequence terminated by BEL; all must vanish without leaving residue.
    def test_ansi_escape_code_scrubbing(self) -> None:
        # Foreground red, clear line, reset codes
        evil_ansi = "Normal text \x1b[31;1mRED ALERT\x1b[0m \x1b[2Jcleared"
        cleaned = self.sanitizer.sanitize(evil_ansi)
        self.assertEqual(cleaned, "Normal text RED ALERT cleared")

        # OSC window title manipulation sequence
        evil_osc = "User \x1b]0;Hacked Title\x07logged in"
        cleaned_osc = self.sanitizer.sanitize(evil_osc)
        self.assertEqual(cleaned_osc, "User logged in")

    # The core CWE-117 property: no raw CR or LF may survive, so an attacker
    # cannot forge a second log record. Visible '\n' tokens remain for forensics.
    def test_cwe_117_newline_injection_defense(self) -> None:
        # Line splitting injection attempt
        injection = "admin\n2026-11-08T00:00:00Z auth.notice: Fake admin login"
        cleaned = self.sanitizer.sanitize(injection)
        # Embedded newline must be escaped to literal \n
        self.assertNotIn("\n", cleaned)
        self.assertIn("admin\\n2026-11-08T00:00:00Z", cleaned)

        # CRLF injection attempt
        crlf_injection = "malicious\r\nINJECTED RECORD"
        cleaned_crlf = self.sanitizer.sanitize(crlf_injection)
        self.assertNotIn("\r", cleaned_crlf)
        self.assertNotIn("\n", cleaned_crlf)
        self.assertIn("malicious\\nINJECTED RECORD", cleaned_crlf)

    # Trojan Source style: the right-to-left override must be removed so the
    # visible text matches the underlying bytes.
    def test_bidi_unicode_override_scrubbing(self) -> None:
        # Right-to-Left Override (U+202E) Trojan Source attempt
        bidi_text = "access_granted_\u202Etxt.exe"
        cleaned = self.sanitizer.sanitize(bidi_text)
        self.assertEqual(cleaned, "access_granted_txt.exe")

    # Control bytes become visible hex escapes; tabs are the one exception that
    # is preserved by default.
    def test_control_character_handling(self) -> None:
        # Null bytes, Bell, Backspace
        polluted = "Safe\x00Text\x07With\x08Controls\tTabsArePreserved"
        cleaned = self.sanitizer.sanitize(polluted)
        self.assertIn("\\x00", cleaned)
        self.assertIn("\\x07", cleaned)
        self.assertIn("\\x08", cleaned)
        self.assertIn("\t", cleaned)  # Tabs preserved by default

    # Output is cut to max_message_length characters.
    def test_max_length_truncation(self) -> None:
        bounded_sanitizer = LogSanitizer(max_message_length=10)
        long_string = "0123456789abcdefghij"
        self.assertEqual(bounded_sanitizer.sanitize(long_string), "0123456789")


# Step 3: Test disk FIFO spool queue persistence, backpressure, and crash recovery
class TestSpoolQueue(unittest.TestCase):
    """Test suite for crash-resilient local disk store-and-forward FIFO queue."""

    # A fresh sanitizer with default settings for every test.
    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="test_spool_")

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # Core FIFO contract: peek does not remove, acknowledge removes from the
    # head, and the telemetry counters track both.
    def test_enqueue_peek_and_acknowledge(self) -> None:
        queue = SpoolQueue(spool_dir=self.test_dir)
        msg1 = LogMessage(message="Message 1")
        msg2 = LogMessage(message="Message 2")

        queue.enqueue(msg1)
        queue.enqueue(msg2)

        # Peek without dequeueing
        peeked = queue.peek(limit=10)
        self.assertEqual(len(peeked), 2)
        self.assertEqual(peeked[0].log_message.message, "Message 1")
        self.assertEqual(peeked[1].log_message.message, "Message 2")

        # Acknowledge first message
        acked = queue.acknowledge(1)
        self.assertEqual(acked, 1)

        # Remaining should be Message 2
        remaining = queue.peek(limit=10)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].log_message.message, "Message 2")

        # Check telemetry status
        status = queue.status()
        self.assertEqual(status["pending_count"], 1)
        self.assertEqual(status["total_enqueued"], 2)
        self.assertEqual(status["total_drained"], 1)

    # Several threads enqueue at once; with the mutex nothing may be lost and
    # the counters must add up exactly.
    def test_concurrent_multithreaded_enqueue(self) -> None:
        """Verify thread-safety when multiple worker threads enqueue concurrently."""
        queue = SpoolQueue(spool_dir=self.test_dir, max_spool_entries=1000)
        threads = []
        messages_per_thread = 50
        num_threads = 4

        def worker(thread_idx: int):
            for i in range(messages_per_thread):
                queue.enqueue(LogMessage(message=f"Thread {thread_idx} - Msg {i}"))

        for idx in range(num_threads):
            t = threading.Thread(target=worker, args=(idx,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        stat = queue.status()
        self.assertEqual(stat["total_enqueued"], num_threads * messages_per_thread)
        self.assertEqual(stat["pending_count"], num_threads * messages_per_thread)

    # Simulates a restart by discarding the first queue object and opening a
    # new one on the same directory; backlog and lifetime counters must survive.
    def test_crash_recovery_persistence(self) -> None:
        # Phase 1: Write records to spool
        queue1 = SpoolQueue(spool_dir=self.test_dir)
        queue1.enqueue(LogMessage(message="Survives reboot 1"))
        queue1.enqueue(LogMessage(message="Survives reboot 2"))
        queue1.acknowledge(1)
        del queue1

        # Phase 2: Instantiate new instance pointing to same directory
        queue2 = SpoolQueue(spool_dir=self.test_dir)
        status = queue2.status()
        self.assertEqual(status["pending_count"], 1)
        self.assertEqual(status["total_enqueued"], 2)
        self.assertEqual(status["total_drained"], 1)

        peeked = queue2.peek(limit=5)
        self.assertEqual(len(peeked), 1)
        self.assertEqual(peeked[0].log_message.message, "Survives reboot 2")

    # Over the entry cap, the OLDEST records are evicted and counted as dropped.
    def test_capacity_backpressure_entry_limit(self) -> None:
        # Enforce max 3 entries
        queue = SpoolQueue(spool_dir=self.test_dir, max_spool_entries=3)
        for i in range(5):
            queue.enqueue(LogMessage(message=f"Log {i}"))

        status = queue.status()
        self.assertEqual(status["pending_count"], 3)
        self.assertEqual(status["dropped_count"], 2)

        # Oldest two (0 and 1) were evicted, entries should be 2, 3, 4
        entries = queue.peek(limit=10)
        messages = [e.log_message.message for e in entries]
        self.assertEqual(messages, ["Log 2", "Log 3", "Log 4"])

    # After purge both the queue and the on-disk files are empty (0 bytes).
    def test_purge(self) -> None:
        queue = SpoolQueue(spool_dir=self.test_dir)
        queue.enqueue(LogMessage(message="To be purged"))
        self.assertEqual(queue.status()["pending_count"], 1)

        queue.purge()
        status = queue.status()
        self.assertEqual(status["pending_count"], 0)
        self.assertEqual(status["disk_usage_bytes"], 0)


class TestSyslogTransport(unittest.TestCase):
    """Test suite for TCP and UDP network transport with mock socket listeners."""

    # Loopback TCP server on an ephemeral port (bind to port 0 lets the OS pick
    # a free one, avoiding collisions). The server collects every received chunk
    # because TCP may split the payload arbitrarily.
    def test_tcp_transport_delivery(self) -> None:
        # Spin up a temporary local TCP server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        received_data = []

        def accept_worker():
            try:
                conn, _ = server_sock.accept()
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    received_data.append(data)
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=accept_worker, daemon=True)
        t.start()

        # Connect client transport
        config = ShipperConfig(
            target_host="127.0.0.1",
            target_port=port,
            protocol="tcp",
            connect_timeout=2.0,
            send_timeout=2.0,
        )
        transport = SyslogTransport(config)
        self.assertTrue(transport.connect())
        self.assertTrue(transport.is_connected)

        # Send test message
        test_payload = b"19 <14>1 2026-11-08 Test\n"
        success = transport.send_bytes(test_payload)
        self.assertTrue(success)

        transport.close()
        server_sock.close()
        t.join(timeout=2.0)

        self.assertEqual(b"".join(received_data), test_payload)

    # Loopback UDP receiver; a datagram must arrive as exactly one packet.
    def test_udp_transport_delivery(self) -> None:
        # Spin up a temporary local UDP receiver
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]

        received_packets = []

        def udp_worker():
            try:
                server_sock.settimeout(2.0)
                data, _ = server_sock.recvfrom(2048)
                received_packets.append(data)
            except OSError:
                pass

        t = threading.Thread(target=udp_worker, daemon=True)
        t.start()

        config = ShipperConfig(
            target_host="127.0.0.1",
            target_port=port,
            protocol="udp",
        )
        transport = SyslogTransport(config)
        self.assertTrue(transport.connect())

        udp_payload = b"<14>1 UDP packet test"
        self.assertTrue(transport.send_bytes(udp_payload))

        transport.close()
        t.join(timeout=2.0)
        server_sock.close()

        self.assertEqual(len(received_packets), 1)
        self.assertEqual(received_packets[0], udp_payload)

    # Jittered delays are random, so only the bounds are asserted: the floor
    # (0.1s) and the configured cap.
    def test_exponential_backoff_bounds(self) -> None:
        config = ShipperConfig(
            reconnect_backoff_initial=1.0,
            reconnect_backoff_max=10.0,
            reconnect_backoff_multiplier=2.0,
        )
        transport = SyslogTransport(config)
        for _ in range(5):
            delay = transport.calculate_backoff()
            self.assertGreaterEqual(delay, 0.1)
            self.assertLessEqual(delay, 10.0)


# Step 4: Test file tailing, rotation detection, and line buffering
class TestFileTailer(unittest.TestCase):
    """Test suite for POSIX file tailing, rotation, and truncation handling."""

    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="test_tailer_")
        self.log_file = Path(self.test_dir) / "app.log"

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # One-shot mode (follow=False) reads an existing file to EOF and stops.
    def test_tail_static_file(self) -> None:
        # Write initial lines
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("Line 1\nLine 2\nLine 3\n")

        tailer = FileTailer(
            filepath=str(self.log_file),
            follow=False,
            start_at_end=False,
        )
        lines = list(tailer.tail())
        self.assertEqual(lines, ["Line 1", "Line 2", "Line 3"])

    # The tailer runs in a background thread. After it has read two lines, the
    # file is truncated in place (same inode); the new line must still be seen.
    # Timing uses short poll intervals and generous join timeouts to stay stable.
    def test_copytruncate_rotation(self) -> None:
        # Simulate logrotate copytruncate: file truncated in-place
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("Initial line 1\nInitial line 2\n")

        tailer = FileTailer(
            filepath=str(self.log_file),
            follow=True,
            start_at_end=False,
            poll_interval=0.05,
        )

        collected = []

        def worker():
            for line in tailer.tail():
                collected.append(line)
                if len(collected) >= 3:
                    tailer.stop()
                    break

        t = threading.Thread(target=worker, daemon=True)
        t.start()

        time.sleep(0.15)
        # Truncate file in place and write fresh content
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("Truncated new line\n")

        t.join(timeout=3.0)
        self.assertIn("Initial line 1", collected)
        self.assertIn("Initial line 2", collected)
        self.assertIn("Truncated new line", collected)

    # After the rename the tailer holds the old inode; the new file at the same
    # path has a new inode. Both files' lines must be delivered.
    def test_rename_and_recreate_rotation(self) -> None:
        # Simulate logrotate 'create' mode: mv app.log app.log.1 && touch app.log
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("Old Inode Line\n")

        tailer = FileTailer(
            filepath=str(self.log_file),
            follow=True,
            start_at_end=False,
            poll_interval=0.05,
        )

        collected = []

        def worker():
            for line in tailer.tail():
                collected.append(line)
                if len(collected) >= 2:
                    tailer.stop()
                    break

        t = threading.Thread(target=worker, daemon=True)
        t.start()

        time.sleep(0.15)
        # Rename old file and create new file with different inode
        rotated_path = Path(self.test_dir) / "app.log.1"
        os.rename(self.log_file, rotated_path)

        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("New Inode Line\n")

        t.join(timeout=3.0)
        self.assertIn("Old Inode Line", collected)
        self.assertIn("New Inode Line", collected)

    # Replace sys.stdin with an in-memory stream, restoring it in finally so
    # other tests are unaffected.
    def test_stdin_tailer(self) -> None:
        import io
        import sys
        
        simulated_input = io.StringIO("First stdin line\nSecond stdin line\n")
        old_stdin = sys.stdin
        try:
            sys.stdin = simulated_input
            tailer = StdinTailer()
            lines = list(tailer.stream())
            self.assertEqual(lines, ["First stdin line", "Second stdin line"])
        finally:
            sys.stdin = old_stdin

    # A line written in two pieces must not be yielded early: nothing is
    # emitted until the newline arrives, then the joined line is emitted once.
    def test_partial_line_buffering(self) -> None:
        tailer = FileTailer(
            filepath=str(self.log_file),
            follow=True,
            start_at_end=False,
            poll_interval=0.05,
        )
        collected = []

        def worker():
            for line in tailer.tail():
                collected.append(line)
                if len(collected) >= 1:
                    tailer.stop()
                    break

        t = threading.Thread(target=worker, daemon=True)
        t.start()

        # Write partial chunk without newline
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("Incomplete part...")
            f.flush()

        time.sleep(0.1)
        self.assertEqual(len(collected), 0)

        # Append remaining part and terminating newline
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write("completed!\n")
            f.flush()

        t.join(timeout=3.0)
        self.assertEqual(collected, ["Incomplete part...completed!"])


class TestEdgeShipperEndToEnd(unittest.TestCase):
    """End-to-end integration tests for store-and-forward spool replay."""

    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="test_e2e_")

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # End-to-end outage scenario: (1) collector down -> messages spooled;
    # (2) collector comes up on the same port; (3) a fresh shipper (simulating a
    # restart) replays the backlog and the spool drains to zero.
    def test_store_and_forward_failover_and_replay(self) -> None:
        # Step 1: Upstream server is completely down (unbound port)
        # A fixed port that nothing listens on, later bound by the test server so the
        # same target config works before and after the 'recovery'. Could collide if
        # the port happens to be in use on the host.
        dead_port = 54321
        config = ShipperConfig(
            target_host="127.0.0.1",
            target_port=dead_port,
            protocol="tcp",
            spool_dir=self.test_dir,
            connect_timeout=0.5,
            send_timeout=0.5,
        )
        shipper = EdgeShipper(config)

        # Ship messages while network is offline
        shipper.ship_message("Message when server down 1")
        shipper.ship_message("Message when server down 2")

        # Verify messages spooled locally
        spool_status = shipper.spooler.status()
        self.assertEqual(spool_status["pending_count"], 2)
        shipper.close()

        # Step 2: Bring up the upstream TCP server on that port
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", dead_port))
        server_sock.listen(5)

        received_wire = []

        def server_thread():
            server_sock.settimeout(4.0)
            try:
                conn, _ = server_sock.accept()
                conn.settimeout(2.0)
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    received_wire.append(data)
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        # Step 3: Reconnect shipper and trigger flush
        reconnected_shipper = EdgeShipper(config)
        flushed_count = reconnected_shipper.flush_spool(batch_size=10)
        self.assertEqual(flushed_count, 2)

        # Verify spool is now empty
        after_status = reconnected_shipper.spooler.status()
        self.assertEqual(after_status["pending_count"], 0)
        self.assertEqual(after_status["total_drained"], 2)

        reconnected_shipper.close()
        t.join(timeout=3.0)
        server_sock.close()

        combined = b"".join(received_wire).decode("utf-8")
        self.assertIn("Message when server down 1", combined)
        self.assertIn("Message when server down 2", combined)


class TestCliInterface(unittest.TestCase):
    """Test suite for CLI command dispatch and argument handling."""

    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="test_cli_")

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # Parser-level check only: flags map to the expected namespace attributes.
    def test_cli_spool_status_json(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["spool-status", "--spool-dir", self.test_dir, "--json"])
        self.assertEqual(args.command, "spool-status")
        self.assertTrue(args.json)

    # Drives main() end to end. Port 65432 is assumed to have no listener, so
    # the message falls back to the spool; purge then clears it.
    def test_cli_send_and_purge(self) -> None:
        # Send message with unreachable target (will spool)
        code = main([
            "send",
            "-m", "CLI Test Log",
            "--host", "127.0.0.1",
            "-p", "65432",
            "--spool-dir", self.test_dir,
        ])
        self.assertEqual(code, 0)

        # Inspect status
        spooler = SpoolQueue(spool_dir=self.test_dir)
        self.assertEqual(spooler.status()["pending_count"], 1)

        # Purge
        code_purge = main(["purge", "--spool-dir", self.test_dir])
        self.assertEqual(code_purge, 0)
        spooler_after = SpoolQueue(spool_dir=self.test_dir)
        self.assertEqual(spooler_after.status()["pending_count"], 0)


if __name__ == "__main__":
    unittest.main()
