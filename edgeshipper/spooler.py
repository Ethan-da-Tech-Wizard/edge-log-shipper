# ==============================================================================
# Program: spooler.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Atomic local store-and-forward FIFO spool queue with disk backpressure guards,
#          providing crash-resilient message buffering during network disconnects.
# ==============================================================================
"""
Atomic Local Store-and-Forward FIFO Spool Queue with Disk Backpressure Guards.

================================================================================
ENGINEERING CONCEPTS & RELIABILITY DESIGN:
================================================================================
Edge computing nodes, IoT gateways, and remote servers frequently operate across
intermittent or high-latency network backhauls (WireGuard mesh tunnels, cellular 4G/5G,
satellite links). During uplink outages, a naive log shipper faces a catastrophic dilemma:
  1. Drop logs in memory (loss of critical security and audit telemetry).
  2. Buffer indefinitely in RAM (leads to Linux kernel Out-Of-Memory (OOM) killer terminating
     the process or freezing the edge gateway).

The Store-and-Forward Spooler resolves this through a persistent disk-backed FIFO queue:
  - Append-Only Journal: Incoming logs are serialized as JSON Lines (JSONL) to disk.
  - Crash-Resilient State: A separate metadata journal tracks byte offsets and sequence IDs.
    If the daemon is killed via SIGKILL or power loss, pending logs remain safely on disk.
  - Disk Backpressure Protection: Edge flash storage (SD cards, eMMC) has finite capacity.
    The spooler enforces strict hard limits (`max_spool_bytes` and `max_spool_entries`).
    When limits are breached, the queue enforces FIFO eviction (dropping the oldest
    records while recording dropped counters) to guarantee the edge node never exhausts disk.
  - Zero External Dependencies: Implemented strictly with standard library `os`, `json`,
    `time`, `uuid`, and `threading`.
"""

from __future__ import annotations

# Stdlib only: json for the JSONL journal/metadata, threading for the mutex,
# uuid for entry ids, pathlib/os/time for file handling.
import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from edgeshipper.models import LogMessage, SpoolEntry


class SpoolQueue:
    """
    Thread-safe, crash-resilient, disk-backed FIFO spool buffer.
    """

    def __init__(
        self,
        spool_dir: str,
        max_spool_bytes: int = 50 * 1024 * 1024,  # 50 Megabytes default
        max_spool_entries: int = 100_000,
        sync_to_disk: bool = False,
    ) -> None:
        """
        Initialize the persistent spool queue.

        Parameters:
            spool_dir: Directory path on the local filesystem to house queue files.
            max_spool_bytes: Maximum byte quota allowed for spool storage.
            max_spool_entries: Maximum number of backlog log records stored before eviction.
            sync_to_disk: If True, calls os.fsync on every append (maximum durability at
                          cost of write I/O operations). Defaults to False (uses OS page cache).
        """
        # Resolve to an absolute path so later chdir() calls or relative inputs
        # cannot silently move the spool.
        self.spool_dir = Path(spool_dir).resolve()
        self.max_spool_bytes = max_spool_bytes
        self.max_spool_entries = max_spool_entries
        self.sync_to_disk = sync_to_disk

        # Ensure directory exists with restrictive POSIX permissions (0700)
        # Mode 0700 below: spooled logs may contain sensitive data, so only the
        # owning user should be able to read them.
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.spool_dir, 0o700)
        except OSError:
            pass  # Non-POSIX or restricted permission environments

        # Two files: the journal holds one JSON record per line (the source of
        # truth for pending entries); the meta file holds cumulative counters.
        self.journal_path = self.spool_dir / "spool_journal.jsonl"
        self.meta_path = self.spool_dir / "spool_meta.json"

        # Concurrency control: Mutex prevents concurrent threads from corrupting
        # journal file pointers and metadata state.
        # A plain (non-reentrant) Lock: every public method takes it once, and the
        # *_unlocked helpers assume the caller already holds it. Never call a public
        # method from inside an *_unlocked helper or it will deadlock.
        self._lock = threading.Lock()

        # Internal in-memory index of unacknowledged entries: list of SpoolEntry
        # The full pending backlog is mirrored in memory (bounded by
        # max_spool_entries) so peek/status never need to re-read the journal.
        self._entries: List[SpoolEntry] = []
        self._dropped_count: int = 0
        self._total_enqueued: int = 0
        self._total_drained: int = 0

        # Load persisted backlog and metadata upon startup
        # Recovery happens in the constructor so a restarted daemon resumes with
        # the backlog the previous run left behind.
        self._initialize_from_disk()

    def _initialize_from_disk(self) -> None:
        """
        Recover queue state from disk upon daemon startup.
        Scans existing journal lines, builds the in-memory entry index,
        and loads cumulative telemetry metrics from the metadata file.
        """
        with self._lock:
            # Metadata is advisory telemetry, so a corrupt file just resets counters
            # while the journal (the real data) is still loaded below.
            # 1. Load cumulative metadata counters if present
            if self.meta_path.exists():
                try:
                    with open(self.meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        self._dropped_count = meta.get("dropped_count", 0)
                        self._total_enqueued = meta.get("total_enqueued", 0)
                        self._total_drained = meta.get("total_drained", 0)
                except Exception:
                    # Corrupt metadata: reset counters gracefully
                    self._dropped_count = 0
                    self._total_enqueued = 0
                    self._total_drained = 0

            # Line-by-line parsing means a torn final line (power loss mid-write) only
            # costs that one record; every earlier record is still recovered.
            # 2. Rehydrate uncommitted entries from the append-only journal
            self._entries.clear()
            if self.journal_path.exists():
                try:
                    with open(self.journal_path, "r", encoding="utf-8") as f:
                        for line in f:
                            clean_line = line.strip()
                            if not clean_line:
                                continue
                            try:
                                entry = SpoolEntry.from_json(clean_line)
                                self._entries.append(entry)
                            except Exception:
                                # Skip any partial/corrupt record caused by abrupt power loss
                                continue
                except Exception:
                    pass

            # The limits may have been lowered since the last run, so re-apply them.
            # Enforce backpressure capacity immediately after load
            self._enforce_capacity_unlocked()

    def _save_meta_unlocked(self) -> None:
        """
        Write metadata state atomically using write-and-rename pattern.
        This guarantees that an unexpected reboot never leaves a half-written JSON file.
        """
        # Write-then-rename: readers (and a crash) see either the complete old file
        # or the complete new one, never a partial write.
        tmp_meta = self.meta_path.with_suffix(".tmp")
        try:
            with open(tmp_meta, "w", encoding="utf-8") as f:
                json.dump({
                    "dropped_count": self._dropped_count,
                    "total_enqueued": self._total_enqueued,
                    "total_drained": self._total_drained,
                    "pending_count": len(self._entries),
                    "last_updated": time.time(),
                }, f)
                f.flush()
                if self.sync_to_disk:
                    os.fsync(f.fileno())
            # Atomic filesystem rename replaces target atomically in POSIX
            # Path.replace is an atomic rename on POSIX when both paths are on the same
            # filesystem, which holds here since the temp file sits beside the target.
            tmp_meta.replace(self.meta_path)
        except Exception:
            # Best-effort cleanup; metadata failures are non-fatal because counters are
            # only telemetry.
            if tmp_meta.exists():
                try:
                    tmp_meta.unlink()
                except OSError:
                    pass

    def _enforce_capacity_unlocked(self) -> None:
        """
        Enforce backpressure constraints on entry count and total disk usage.
        When bounds are exceeded, drops the oldest records (FIFO eviction).
        Caller must hold self._lock.
        """
        # Rewriting the journal is expensive, so only do it when something was
        # actually evicted.
        need_compaction = False

        # Check entry count ceiling
        # Backpressure policy is drop-oldest: for logs the newest events are
        # usually the most valuable, and the node must never fill its disk.
        while len(self._entries) > self.max_spool_entries:
            self._entries.pop(0)  # Evict oldest entry
            self._dropped_count += 1
            need_compaction = True

        # Check total estimated byte quota
        # The on-disk journal is only shrunk by _rewrite_journal_unlocked, which runs
        # after this loop, so re-stat'ing the file would never show progress and the
        # loop would evict every entry. Instead measure once, then subtract the
        # serialized size (JSON line plus newline, in UTF-8) of each evicted entry.
        current_disk_bytes = self.get_disk_usage_unlocked()
        while current_disk_bytes > self.max_spool_bytes and self._entries:
            evicted = self._entries.pop(0)
            current_disk_bytes -= len((evicted.to_json() + "\n").encode("utf-8"))
            self._dropped_count += 1
            need_compaction = True

        if need_compaction:
            self._rewrite_journal_unlocked()
            self._save_meta_unlocked()

    # Compaction = write all surviving entries to a temp file, then atomically
    # replace the journal. Used after eviction, acknowledgement and attempt-count
    # updates, so the journal always matches the in-memory list.
    def _rewrite_journal_unlocked(self) -> None:
        """
        Atomically compact the journal file, writing only active entries.
        Uses atomic file replacement (write to temp file, then os.replace).
        Caller must hold self._lock.
        """
        tmp_journal = self.journal_path.with_suffix(".tmp")
        try:
            with open(tmp_journal, "w", encoding="utf-8") as f:
                for entry in self._entries:
                    f.write(entry.to_json() + "\n")
                f.flush()
                if self.sync_to_disk:
                    os.fsync(f.fileno())
            tmp_journal.replace(self.journal_path)
        except Exception:
            if tmp_journal.exists():
                try:
                    tmp_journal.unlink()
                except OSError:
                    pass

    def enqueue(self, log_message: LogMessage) -> SpoolEntry:
        """
        Enqueue a new log record onto the persistent spool queue.

        Parameters:
            log_message: The LogMessage object to persist.

        Returns:
            The created SpoolEntry containing assigned unique ID.
        """
        # 16 hex chars (64 bits of randomness) is ample to be unique within one
        # bounded spool and keeps journal lines compact.
        entry_id = uuid.uuid4().hex[:16]
        entry = SpoolEntry(
            id=entry_id,
            created_at=time.time(),
            log_message=log_message,
            attempts=0,
        )

        with self._lock:
            # Append serialized record to active journal
            # Disk Durability Strategy:
            # - Write buffer flush ensures userspace C stdio buffers are passed to kernel page cache.
            # - os.fsync() forces kernel to commit dirty pages to non-volatile physical storage,
            #   preventing data loss during immediate power loss at the cost of disk I/O latency.
            # Append mode: a crash can at worst leave one truncated last line, which
            # the loader skips. Append is cheap compared with rewriting the file.
            serialized_line = entry.to_json() + "\n"
            with open(self.journal_path, "a", encoding="utf-8") as f:
                f.write(serialized_line)
                f.flush()
                if self.sync_to_disk:
                    os.fsync(f.fileno())

            # Keep the in-memory index in step with the journal under the same lock.
            self._entries.append(entry)
            self._total_enqueued += 1

            # Enforce capacity and backpressure constraints after append
            self._enforce_capacity_unlocked()

            # Update metadata periodically or on write
            self._save_meta_unlocked()

        return entry

    def peek(self, limit: int = 100) -> List[SpoolEntry]:
        """
        Read up to `limit` pending entries from head of queue without removing them.
        Allows the transport sender to inspect and attempt transmission.

        Parameters:
            limit: Maximum number of entries to return.

        Returns:
            List of SpoolEntry records.
        """
        with self._lock:
            # Return a copy so callers cannot mutate the queue's internal list.
            return list(self._entries[:limit])

    def acknowledge(self, count: int) -> int:
        """
        Acknowledge successful transmission of the oldest `count` entries,
        removing them from the queue and reclaiming disk space.

        Parameters:
            count: Number of successfully dispatched entries to remove.

        Returns:
            Number of entries actually dequeued.
        """
        if count <= 0:
            return 0

        with self._lock:
            # Clamp so over-acknowledging cannot raise or corrupt the counters.
            actual_count = min(count, len(self._entries))
            if actual_count > 0:
                # FIFO: acknowledgement always removes from the head, matching the order
                # in which flush_spool transmitted them.
                del self._entries[:actual_count]
                self._total_drained += actual_count

                # Compact the journal on disk
                self._rewrite_journal_unlocked()
                self._save_meta_unlocked()

            return actual_count

    def increment_attempts(self, entry_ids: List[str]) -> None:
        """
        Increment the failed attempt counter for the specified entries.
        Allows tracking persistent delivery failures.

        Parameters:
            entry_ids: List of SpoolEntry IDs whose transmission failed.
        """
        # Set membership makes the scan below O(n) rather than O(n*m).
        id_set = set(entry_ids)
        with self._lock:
            modified = False
            for entry in self._entries:
                if entry.id in id_set:
                    entry.attempts += 1
                    modified = True
            if modified:
                self._rewrite_journal_unlocked()

    # Counts only the journal and meta files, not the directory as a whole.
    def get_disk_usage_unlocked(self) -> int:
        """Calculate total byte footprint of spool files on disk. Caller holds lock."""
        total = 0
        if self.journal_path.exists():
            try:
                total += self.journal_path.stat().st_size
            except OSError:
                pass
        if self.meta_path.exists():
            try:
                total += self.meta_path.stat().st_size
            except OSError:
                pass
        return total

    def status(self) -> Dict[str, Any]:
        """
        Generate comprehensive operational telemetry metrics for health audits.

        Returns:
            Dictionary containing queue depth, disk usage, dropped counts, etc.
        """
        with self._lock:
            disk_bytes = self.get_disk_usage_unlocked()
            pending_count = len(self._entries)
            # Age of the head entry shows how long the backlog has been stuck, which is
            # the most useful single health signal for an outage.
            oldest_age = 0.0
            if self._entries:
                oldest_age = max(0.0, time.time() - self._entries[0].created_at)

            return {
                "spool_dir": str(self.spool_dir),
                "pending_count": pending_count,
                "disk_usage_bytes": disk_bytes,
                "disk_usage_mb": round(disk_bytes / (1024 * 1024), 3),
                "max_spool_bytes": self.max_spool_bytes,
                "max_spool_entries": self.max_spool_entries,
                "dropped_count": self._dropped_count,
                "total_enqueued": self._total_enqueued,
                "total_drained": self._total_drained,
                "oldest_entry_age_seconds": round(oldest_age, 2),
            }

    # Destructive and irreversible: deletes the journal and metadata and zeroes
    # all counters (including the lifetime dropped/enqueued/drained totals).
    def purge(self) -> None:
        """Completely purge all spool data and reset telemetry counters."""
        with self._lock:
            self._entries.clear()
            self._dropped_count = 0
            self._total_enqueued = 0
            self._total_drained = 0
            if self.journal_path.exists():
                try:
                    self.journal_path.unlink()
                except OSError:
                    pass
            if self.meta_path.exists():
                try:
                    self.meta_path.unlink()
                except OSError:
                    pass
