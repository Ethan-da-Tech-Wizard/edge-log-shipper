# ==============================================================================
# Program: cli.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Command-line interface parser and dispatcher supporting one-shot syslog
#          delivery, continuous file tailing, stdin ingestion, and spool queue management.
# ==============================================================================
"""
Command-Line Interface (CLI) for Edge Log Shipper.

================================================================================
CLI WORKFLOWS & OPERATIONAL CAPABILITIES:
================================================================================
1. One-Shot Delivery (`send`):
   Useful for shell scripts, cron jobs, backup hooks, and monitoring probes:
     edgeshipper send --host 10.100.0.1 --port 514 --message "Backup completed in 42s"

2. File & Stdin Streaming (`tail`):
   Tail application logs or stream pipeline data:
     edgeshipper tail --file /var/log/nginx/access.log --host 10.100.0.1
     journalctl -u my-service -f | edgeshipper tail --host 10.100.0.1

3. Spool Management (`spool-status`, `flush`, `purge`):
   Inspect local buffer health, queue depth, and trigger manual store-and-forward replay.
"""

# Postponed evaluation of annotations keeps the type hints below cheap and
# allows the newer annotation syntax on the oldest supported Python (3.8).
# Layout: build_parser() declares the subcommands, main() parses argv and dispatches to the
# cmd_* handlers. Handlers return exit codes (never sys.exit) so tests call main() directly.
# Run: python -m edgeshipper <command> --help    Test: python3 -m pytest -q
from __future__ import annotations

# Standard library only: the project is deliberately zero-dependency so it can
# be dropped onto minimal edge devices without a package install step.
import argparse
import json
import os
import sys
from typing import List, Optional

from edgeshipper.models import ShipperConfig, parse_facility, parse_severity
from edgeshipper.shipper import EdgeShipper
from edgeshipper.spooler import SpoolQueue
from edgeshipper.tailer import FileTailer, StdinTailer


# The parser is built in a function (not at import time) so tests can call
# main() repeatedly with different argv lists and get a fresh parser each time.
def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser with the send/tail/spool-status/flush/purge subcommands.

    Called by main() on every invocation (and by tests), so it has no side effects.
    The networking flags live in the nested add_common_flags helper and are shared by
    every command that can reach a collector.

    Returns:
        The configured ArgumentParser; the chosen subcommand ends up in args.command.
    """
    parser = argparse.ArgumentParser(
        prog="edgeshipper",
        description="Zero-dependency edge log streaming daemon with store-and-forward spooling.",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="edgeshipper 1.0.0",
    )

    # Subparsers for commands
    # required=True makes argparse itself reject a missing subcommand with a usage
    # error, instead of us handling args.command being None.
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Helper function to add common networking and spooling flags
    # Networking, framing and syslog-header flags shared by every subcommand that
    # can talk to a collector (send, tail, flush). Defined once so the commands
    # cannot drift apart in their defaults.
    def add_common_flags(subp: argparse.ArgumentParser) -> None:
        subp.add_argument(
            "--host",
            default="127.0.0.1",
            help="Destination syslog collector IP/host (default: 127.0.0.1)",
        )
        subp.add_argument(
            "-p", "--port",
            type=int,
            default=514,
            help="Destination syslog port (default: 514)",
        )
        subp.add_argument(
            "--protocol",
            choices=["tcp", "udp"],
            default="tcp",
            help="Transport protocol: 'tcp' or 'udp' (default: tcp)",
        )
        subp.add_argument(
            "--format",
            dest="syslog_format",
            choices=["rfc5424", "rfc3164"],
            default="rfc5424",
            help="Syslog protocol format (default: rfc5424)",
        )
        subp.add_argument(
            "--framing",
            choices=["octet", "newline"],
            default="octet",
            help="TCP framing method: 'octet' (RFC 6587) or 'newline' (default: octet)",
        )
        subp.add_argument(
            # The spool lives on local disk so messages survive an upstream outage or a
            # process crash; /tmp is only a convenient default, production should point
            # this at persistent storage.
            "--spool-dir",
            default="/tmp/edgeshipper_spool",
            help="Local filesystem directory for spool queue (default: /tmp/edgeshipper_spool)",
        )
        subp.add_argument(
            # Sanitization (CWE-117 log-injection defense) is ON by default; this is an
            # explicit opt-out for trusted, already-clean inputs.
            "--no-sanitize",
            action="store_true",
            help="Disable CWE-117 log injection sanitization",
        )
        subp.add_argument(
            "--app-name",
            default="edgeshipper",
            help="Application tag embedded in syslog header (default: edgeshipper)",
        )
        subp.add_argument(
            "--facility",
            default="user",
            help="Default syslog facility (name or 0-23, default: user)",
        )
        subp.add_argument(
            "--severity",
            default="info",
            help="Default syslog severity (name or 0-7, default: info)",
        )

    # --- Subcommand: send (one-shot delivery for scripts/cron) ---
    # Subcommand: send
    send_parser = subparsers.add_parser("send", help="Send a single log message")
    send_parser.add_argument(
        "-m", "--message",
        required=True,
        help="Log message text to transmit",
    )
    add_common_flags(send_parser)

    # --- Subcommand: tail (stream a file or stdin continuously) ---
    # Subcommand: tail
    tail_parser = subparsers.add_parser("tail", help="Tail a log file or stream from stdin")
    tail_parser.add_argument(
        "-f", "--file",
        help="Path to log file to tail (if omitted, reads from stdin)",
    )
    tail_parser.add_argument(
        "--no-follow",
        action="store_true",
        help="Read to current EOF and exit instead of following (-f)",
    )
    tail_parser.add_argument(
        "--from-start",
        action="store_true",
        help="Read file from beginning instead of seeking to EOF on start",
    )
    tail_parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.2,
        help="Polling interval in seconds for file checks (default: 0.2s)",
    )
    add_common_flags(tail_parser)

    # --- Subcommand: spool-status (read-only inspection; needs no network flags,
    # so it only declares --spool-dir) ---
    # Subcommand: spool-status
    status_parser = subparsers.add_parser("spool-status", help="Inspect local spool queue status")
    status_parser.add_argument(
        "--spool-dir",
        default="/tmp/edgeshipper_spool",
        help="Spool directory to inspect (default: /tmp/edgeshipper_spool)",
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output status as structured JSON",
    )

    # --- Subcommand: flush (manually replay spooled records upstream) ---
    # Subcommand: flush
    flush_parser = subparsers.add_parser("flush", help="Drain pending spool buffer to upstream server")
    add_common_flags(flush_parser)
    flush_parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Maximum records to drain per batch (default: 100)",
    )

    # --- Subcommand: purge (destructive: discards all spooled records) ---
    # Subcommand: purge
    purge_parser = subparsers.add_parser("purge", help="Clear all pending logs in local spool")
    purge_parser.add_argument(
        "--spool-dir",
        default="/tmp/edgeshipper_spool",
        help="Spool directory to wipe (default: /tmp/edgeshipper_spool)",
    )

    return parser


def create_config_from_args(args: argparse.Namespace) -> ShipperConfig:
    """Map a parsed CLI namespace onto a typed ShipperConfig.

    Args:
        args: Namespace from build_parser() for send, tail or flush (needs host, port,
            protocol, syslog_format, framing, spool_dir, app_name, facility, severity).

    Returns:
        A ShipperConfig with numeric facility/severity codes and sanitize inverted from
        --no-sanitize.

    Raises:
        ValueError: If --facility or --severity is neither a known name nor in range
            (raised by parse_facility / parse_severity).
    """
    # Facility/severity accept either a symbolic name or a number; parse_*
    # validates them and returns the numeric code stored in the config.
    # Numeric codes (not names) are what the RFC 5424 priority value is built from.
    facility_code = parse_facility(args.facility)
    severity_code = parse_severity(args.severity)

    return ShipperConfig(
        target_host=args.host,
        target_port=args.port,
        protocol=args.protocol,
        syslog_format=args.syslog_format,
        framing=args.framing,
        spool_dir=args.spool_dir,
        # getattr with a default because spool-related subcommands that reach this
        # helper may not define --no-sanitize; invert the flag into a positive bool.
        sanitize=not getattr(args, "no_sanitize", False),
        app_name=args.app_name,
        facility=facility_code,
        severity=severity_code,
    )


def cmd_send(args: argparse.Namespace) -> int:
    """Run `send`: ship one message, spooling it locally if the collector is down.

    Args:
        args: Parsed namespace including message plus the common networking flags.

    Returns:
        0 if the message was delivered or safely spooled, 1 if it could neither be
        sent nor spooled. Side effects: opens a socket and the spool directory.
    """
    config = create_config_from_args(args)
    # The shipper owns sockets and spool file handles; every command below closes
    # it in a finally block so resources are released on any exit path.
    shipper = EdgeShipper(config)
    try:
        # On send failure the message goes to the spool, so False here means both the network and the disk spool failed.
        success = shipper.ship_message(args.message)
        if success:
            # ship_message returns True both when delivered and when safely spooled, so
            # the pending count is how we tell the two outcomes apart for the user.
            spool_stat = shipper.spooler.status()
            if spool_stat["pending_count"] > 0:
                print(f"[edgeshipper] Upstream unreachable. Message spooled to {config.spool_dir}")
            else:
                print(f"[edgeshipper] Sent message to {config.protocol.upper()}://{config.target_host}:{config.target_port}")
            return 0
        else:
            print("[edgeshipper] ERROR: Failed to ship or spool message.", file=sys.stderr)
            return 1
    finally:
        shipper.close()


def cmd_tail(args: argparse.Namespace) -> int:
    """Run `tail`: stream a file (or stdin) to the collector until EOF or Ctrl-C.

    Args:
        args: Parsed namespace with file, no_follow, from_start, poll_interval and the
            common networking flags.

    Returns:
        0 on normal completion or Ctrl-C. Blocks for the life of the stream in follow mode.
    """
    config = create_config_from_args(args)
    shipper = EdgeShipper(config)

    try:
        # With --file we tail a path; otherwise fall back to reading stdin (pipes).
        if args.file:
            print(f"[edgeshipper] Tailing file: {args.file} -> {config.protocol.upper()}://{config.target_host}:{config.target_port}")
            # follow/start_at_end are inverted CLI flags: the default is `tail -f` behaviour (start at EOF, keep following).
            tailer = FileTailer(
                filepath=args.file,
                follow=not args.no_follow,
                start_at_end=not args.from_start,
                poll_interval=args.poll_interval,
            )
            # run_stream consumes the generator, shipping each line and spooling on failure; it only returns when the stream ends.
            shipper.run_stream(tailer.tail())
        else:
            print(f"[edgeshipper] Streaming from stdin -> {config.protocol.upper()}://{config.target_host}:{config.target_port}")
            tailer = StdinTailer()
            shipper.run_stream(tailer.stream())
        return 0
    # Ctrl-C is the normal way to stop a follow-mode tail, so it is a clean exit
    # (status 0) rather than an error.
    except KeyboardInterrupt:
        print("\n[edgeshipper] Stopped by user signal.")
        return 0
    finally:
        shipper.close()


def cmd_spool_status(args: argparse.Namespace) -> int:
    """Run `spool-status`: print queue depth, disk use and counters (read-only, no network).

    Args:
        args: Parsed namespace with spool_dir and optional json flag.

    Returns:
        Always 0.
    """
    # Opening the queue re-reads the journal, so the numbers reflect what a daemon restart would recover.
    spooler = SpoolQueue(spool_dir=args.spool_dir)
    stat = spooler.status()

    # --json emits machine-readable output for monitoring scripts; the default is
    # a human-aligned report.
    if getattr(args, "json", False):
        print(json.dumps(stat, indent=2))
    else:
        print(f"Spool Directory:     {stat['spool_dir']}")
        print(f"Pending Messages:    {stat['pending_count']}")
        print(f"Disk Usage:          {stat['disk_usage_bytes']} bytes ({stat['disk_usage_mb']} MB)")
        print(f"Dropped (Overflow):  {stat['dropped_count']}")
        print(f"Total Enqueued:      {stat['total_enqueued']}")
        print(f"Total Drained:       {stat['total_drained']}")
        print(f"Oldest Entry Age:    {stat['oldest_entry_age_seconds']}s")
    return 0


def cmd_flush(args: argparse.Namespace) -> int:
    """Run `flush`: manually replay everything in the spool to the collector.

    Args:
        args: Parsed namespace with batch_size and the common networking flags.

    Returns:
        Always 0, even if the collector is down (records then simply stay spooled and
        the remaining count is printed).
    """
    config = create_config_from_args(args)
    shipper = EdgeShipper(config)
    try:
        # batch_size bounds memory per round; the loop below keeps going until the spool is empty or upstream stops accepting.
        print(f"[edgeshipper] Flushing spool buffer to {config.target_host}:{config.target_port}...")
        # Drain in batches until flush_spool reports zero. It returns 0 either when
        # the spool is empty or when upstream is still unreachable, so the loop ends
        # in both cases without spinning forever.
        total_flushed = 0
        while True:
            flushed = shipper.flush_spool(batch_size=args.batch_size)
            if flushed == 0:
                break
            total_flushed += flushed

        stat = shipper.spooler.status()
        print(f"[edgeshipper] Flushed {total_flushed} messages. Remaining in spool: {stat['pending_count']}")
        return 0
    finally:
        shipper.close()


def cmd_purge(args: argparse.Namespace) -> int:
    """Run `purge`: permanently delete every spooled record and reset counters.

    Destructive and not reversible; there is deliberately no confirmation prompt so it
    can be used from scripts.

    Args:
        args: Parsed namespace with spool_dir.

    Returns:
        Always 0.
    """
    spooler = SpoolQueue(spool_dir=args.spool_dir)
    spooler.purge()
    print(f"[edgeshipper] Purged all records in spool directory: {args.spool_dir}")
    return 0


# argv is injectable for tests; None makes argparse read sys.argv[1:].
def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point (`python -m edgeshipper` and the console script).

    Args:
        argv: Argument list to parse; None means sys.argv[1:].

    Returns:
        The selected subcommand's exit code; 1 if no handler matched.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "send":
        return cmd_send(args)
    elif args.command == "tail":
        return cmd_tail(args)
    elif args.command == "spool-status":
        return cmd_spool_status(args)
    elif args.command == "flush":
        return cmd_flush(args)
    elif args.command == "purge":
        return cmd_purge(args)
    # Defensive fallback; argparse's required subparser should make this unreachable.
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
