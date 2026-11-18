# Program: edge-log-shipper - spooler.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Implements SpoolQueue, a thread-safe on-disk FIFO queue (JSON lines journal plus metadata file) that holds logs while the network is down.
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

import json
import os
import shutil
# threading.Lock keeps concurrent callers from corrupting the files.
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
        # Turn the text path into an absolute Path object.
        self.spool_dir = Path(spool_dir).resolve()
        self.max_spool_bytes = max_spool_bytes
        self.max_spool_entries = max_spool_entries
        self.sync_to_disk = sync_to_disk

        # Ensure directory exists with restrictive POSIX permissions (0700)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.spool_dir, 0o700)
        except OSError:
            pass  # Non-POSIX or restricted permission environments

        # Journal file: one JSON record per line, one line per queued message.
        self.journal_path = self.spool_dir / "spool_journal.jsonl"
        # Metadata file: counters that survive restarts.
        self.meta_path = self.spool_dir / "spool_meta.json"

        # Concurrency control: Mutex prevents concurrent threads from corrupting
        # journal file pointers and metadata state.
        self._lock = threading.Lock()

        # Internal in-memory index of unacknowledged entries: list of SpoolEntry
        self._entries: List[SpoolEntry] = []
        self._dropped_count: int = 0
        self._total_enqueued: int = 0
        self._total_drained: int = 0

        # Load persisted backlog and metadata upon startup
        # Reload anything left over from a previous run.
        self._initialize_from_disk()

    def _initialize_from_disk(self) -> None:
        """
        Recover queue state from disk upon daemon startup.
        Scans existing journal lines, builds the in-memory entry index,
        and loads cumulative telemetry metrics from the metadata file.
        """
        with self._lock:
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

            # Enforce backpressure capacity immediately after load
            self._enforce_capacity_unlocked()

    def _save_meta_unlocked(self) -> None:
        """
        Write metadata state atomically using write-and-rename pattern.
        This guarantees that an unexpected reboot never leaves a half-written JSON file.
        """
        # Write to a temporary file first so a crash cannot leave a half-written file.
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
            # Swap the finished temp file into place in one step.
            tmp_meta.replace(self.meta_path)
        except Exception:
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
        need_compaction = False

        # Check entry count ceiling
        while len(self._entries) > self.max_spool_entries:
            # The oldest entry is at index 0 (first in, first out).
            self._entries.pop(0)  # Evict oldest entry
            self._dropped_count += 1
            need_compaction = True

        # Check total estimated byte quota
        # Measure the files on disk before checking the byte limit.
        current_disk_bytes = self.get_disk_usage_unlocked()
        while current_disk_bytes > self.max_spool_bytes and self._entries:
            self._entries.pop(0)
            self._dropped_count += 1
            need_compaction = True
            current_disk_bytes = self.get_disk_usage_unlocked()

        if need_compaction:
            # Rewrite the journal so the file matches the in-memory list.
            self._rewrite_journal_unlocked()
            self._save_meta_unlocked()

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
        # Random 16-character id so each entry can be told apart.
        entry_id = uuid.uuid4().hex[:16]
        entry = SpoolEntry(
            id=entry_id,
            created_at=time.time(),
            log_message=log_message,
            attempts=0,
        )

        with self._lock:
            # Append serialized record to active journal
            serialized_line = entry.to_json() + "\n"
            # Append mode: add one line at the end without touching older lines.
            with open(self.journal_path, "a", encoding="utf-8") as f:
                f.write(serialized_line)
                f.flush()
                if self.sync_to_disk:
                    os.fsync(f.fileno())

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
            # Return a copy so callers cannot change the queue by accident.
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
            actual_count = min(count, len(self._entries))
            if actual_count > 0:
                # Remove the oldest entries that were delivered.
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
        # A set makes the id lookup below fast.
        id_set = set(entry_ids)
        with self._lock:
            modified = False
            for entry in self._entries:
                if entry.id in id_set:
                    entry.attempts += 1
                    modified = True
            if modified:
                self._rewrite_journal_unlocked()

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
            # Age in seconds of the oldest waiting message (0 when empty).
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
