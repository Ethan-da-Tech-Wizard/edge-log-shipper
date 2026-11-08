"""
POSIX Inode-Aware File Tailer with Log Rotation Detection and Stdin Streaming.

================================================================================
POSIX FILESYSTEM MECHANICS & LOG ROTATION DEEP DIVE:
================================================================================
Tailing log files reliably in production Linux environments (e.g. `/var/log/syslog`,
`/var/log/messages`, or Docker/systemd service logs) involves critical filesystem
subtleties that naive `file.read()` loops fail to handle:

1. File Descriptors vs Directory Paths:
   In POSIX filesystems (ext4, XFS, Btrfs), a directory entry (dentry) is merely a pointer
   (hard link) binding a pathname to an underlying index node (inode). An open file handle
   references the inode directly, not the pathname.

2. The Two Canonical Linux Log Rotation Strategies:
   A. Strategy 1: Rename & Recreate ('create' mode in logrotate):
      1. `logrotate` invokes `rename("/var/log/app.log", "/var/log/app.log.1")`.
      2. It creates a brand new `/var/log/app.log` with a fresh inode.
      3. It signals the application (SIGHUP) to reopen its log file.
      Consequence for Tailer:
      The tailer's existing open file descriptor continues reading from the old inode
      (now named `app.log.1`).
      Detection:
      We compare the inode of our open file handle (`os.fstat(fd).st_ino`) against the
      inode of the file currently at the filesystem path (`os.stat(path).st_ino`).
      When they diverge:
        a) Drain any final lines remaining in the old file handle.
        b) Close the old file handle.
        c) Open the new file handle at the path.
        d) Reset our read offset to 0.

   B. Strategy 2: In-Place Truncation ('copytruncate' mode in logrotate):
      Used for software that cannot be signaled to close its log handle.
      1. `logrotate` copies the contents of `app.log` to `app.log.1`.
      2. It truncates `app.log` in-place to 0 bytes (`truncate(fd, 0)`).
      Consequence for Tailer:
      The inode NEVER changes! But the file size becomes strictly less than our
      current read pointer (`file_stat.st_size < current_read_offset`).
      Detection:
      When current file size < our stored byte offset, the file was truncated in place.
      We must immediately seek to byte offset 0.

3. Incomplete Line Buffering:
   Applications write logs using user-space I/O buffers (e.g. 4096-byte glibc buffer).
   If a log line is emitted in chunks or split across buffer flushes, reading raw bytes
   can yield partial fragments without a terminating newline (`\\n`).
   The tailer maintains an unconsumed string buffer and only yields complete lines.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Iterator, Optional


class FileTailer:
    """
    Production-grade, rotation-safe file tailer tracking POSIX inodes and offsets.
    """

    def __init__(
        self,
        filepath: str,
        follow: bool = True,
        start_at_end: bool = True,
        poll_interval: float = 0.2,
    ) -> None:
        """
        Configure the file tailer.

        Parameters:
            filepath: Path to the target log file on disk.
            follow: If True, blocks and continuously polls for new lines (tail -f).
                    If False, reads existing file contents to EOF and stops.
            start_at_end: If True and file exists, seeks to current EOF on startup
                          (ignoring historical lines). If False, starts from byte 0.
            poll_interval: Sleep duration in seconds between idle filesystem checks.
        """
        self.filepath = Path(filepath).resolve()
        self.follow = follow
        self.start_at_end = start_at_end
        self.poll_interval = poll_interval

        self._file_handle = None
        self._current_inode: Optional[int] = None
        self._current_dev: Optional[int] = None
        self._buffer: str = ""
        self._should_stop: bool = False

    def stop(self) -> None:
        """Signal the tailing loop to terminate gracefully."""
        self._should_stop = True

    def _open_file(self) -> bool:
        """
        Open the target file and record its inode and device ID.

        Returns:
            True if file opened successfully, False if file does not exist yet.
        """
        if not self.filepath.exists():
            return False

        try:
            # Open file in binary or text mode with explicit utf-8 handling
            f = open(self.filepath, "r", encoding="utf-8", errors="replace")
            stat_info = os.fstat(f.fileno())

            self._file_handle = f
            self._current_inode = stat_info.st_ino
            self._current_dev = stat_info.st_dev

            # If instructed to start at end (tail -f behavior), seek to current EOF
            if self.start_at_end:
                f.seek(0, os.SEEK_END)

            return True
        except (OSError, IOError):
            self._file_handle = None
            return False

    def _check_rotation(self) -> bool:
        """
        Inspect the target path on disk to detect if log rotation occurred.

        Detects:
          1. Inode divergence (rename-and-recreate rotation).
          2. File truncation (copytruncate rotation).

        Returns:
            True if a rotation or truncation was detected and handled.
        """
        if self._file_handle is None:
            return False

        try:
            # Check status of currently open file handle
            current_fstat = os.fstat(self._file_handle.fileno())
            current_offset = self._file_handle.tell()

            # Case A: Truncation detection ('copytruncate')
            # If current file size is smaller than our read offset, the file was truncated.
            if current_fstat.st_size < current_offset:
                # Seek to beginning of the truncated file
                self._file_handle.seek(0, os.SEEK_SET)
                return True

            # Case B: Inode divergence ('create' / rename rotation)
            # Check what inode is currently located at self.filepath on disk
            if self.filepath.exists():
                path_stat = self.filepath.stat()
                if path_stat.st_ino != self._current_inode or path_stat.st_dev != self._current_dev:
                    # Inode has changed! A new file was placed at this path.
                    # Drain any remaining bytes from the old file handle first:
                    trailing_data = self._file_handle.read()
                    if trailing_data:
                        self._buffer += trailing_data

                    # Close old file handle
                    try:
                        self._file_handle.close()
                    except OSError:
                        pass

                    # Open new file handle at target path
                    new_f = open(self.filepath, "r", encoding="utf-8", errors="replace")
                    new_stat = os.fstat(new_f.fileno())
                    self._file_handle = new_f
                    self._current_inode = new_stat.st_ino
                    self._current_dev = new_stat.st_dev
                    self._file_handle.seek(0, os.SEEK_SET)
                    return True

        except (OSError, IOError):
            pass

        return False

    def tail(self) -> Iterator[str]:
        """
        Generator yielding individual sanitized lines as they are appended to the file.

        Yields:
            Complete, individual log lines (without trailing newline).
        """
        # Wait for file to appear if it does not yet exist
        while not self._open_file() and not self._should_stop:
            if not self.follow:
                return
            time.sleep(self.poll_interval)

        try:
            while not self._should_stop:
                # Check for log rotation or truncation before each read pass
                self._check_rotation()

                if self._file_handle is None:
                    if not self._open_file():
                        time.sleep(self.poll_interval)
                        continue

                # Read available chunk from file handle
                chunk = self._file_handle.readline()

                if chunk:
                    # If chunk ends with newline, we have a complete line
                    if chunk.endswith("\n") or chunk.endswith("\r"):
                        complete_line = self._buffer + chunk.rstrip("\r\n")
                        self._buffer = ""
                        yield complete_line
                    else:
                        # Partial line read: accumulate in buffer until trailing newline arrives
                        self._buffer += chunk
                else:
                    # Reached EOF of currently available data
                    if not self.follow:
                        # Flush any remaining buffer on non-follow exit
                        if self._buffer:
                            yield self._buffer
                            self._buffer = ""
                        break

                    # Idle sleep before next poll to prevent busy-waiting / 100% CPU burn
                    time.sleep(self.poll_interval)

        finally:
            if self._file_handle is not None:
                try:
                    self._file_handle.close()
                except OSError:
                    pass
                self._file_handle = None


class StdinTailer:
    """
    Streams log records from standard input (sys.stdin).
    Enables piping pipelines: `journalctl -f | edgeshipper tail` or `cat access.log | edgeshipper`.
    """

    def __init__(self) -> None:
        self._should_stop = False

    def stop(self) -> None:
        """Signal the stdin streamer to stop."""
        self._should_stop = True

    def stream(self) -> Iterator[str]:
        """
        Generator yielding individual log lines read from standard input.

        Yields:
            Complete lines stripped of trailing newlines.
        """
        try:
            for line in sys.stdin:
                if self._should_stop:
                    break
                clean_line = line.rstrip("\r\n")
                if clean_line:
                    yield clean_line
        except (KeyboardInterrupt, BrokenPipeError):
            pass
