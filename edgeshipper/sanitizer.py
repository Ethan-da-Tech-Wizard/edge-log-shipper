# Program: edge-log-shipper - sanitizer.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Cleans untrusted log text (ANSI escapes, bidi overrides, newlines, control characters, over-long input) so each log record stays one safe line.
"""
Log Sanitizer and CWE-117 (Improper Output Handling for Logs) Defense Engine.

================================================================================
SECURITY ARCHITECTURE & THREAT VECTORS (CWE-117 EXPLAINED):
================================================================================
CWE-117 occurs when an application writes unvalidated user-controlled input
directly into system or audit logs without sufficient neutralization.

On edge devices, IoT nodes, and servers, logs are parsed by upstream SIEM systems
(Splunk, Elastic, Graylog), viewed in administrative terminals via `tail -f` or
`less -R`, and ingested by incident response automation.

Attacks mitigated by this module:
1. Log Forgery / Line Splitting:
   An attacker supplies an input string such as:
     "admin\\n2026-11-08T07:00:00Z auth.info: User admin logged in successfully"
   If unescaped, the embedded newline splits the record into two distinct log entries,
   allowing the adversary to fabricate audit trail entries or cover up malicious actions.

2. Terminal Escape Sequence Injection (ANSI Spoofing):
   Terminals interpret ANSI escape codes (e.g., ESC `\x1b[`). Attackers can inject:
     - Clear screen commands: `\\x1b[2J`
     - Terminal cursor repositioning: `\\x1b[H`
     - Foreground/Background color spoofing: `\\x1b[30;47m` (making text invisible)
     - Terminal emulator exploits (OSC sequences, clipboard injection via OSC 52,
       window title manipulation, or terminal command execution in vulnerable emulators).

3. Unicode Bidirectional (Bidi) Text Spoofing:
   Attackers use unicode directional overrides (e.g., U+202E Right-to-Left Override)
   to visually alter file paths or usernames in modern UTF-8 terminals while retaining
   different underlying bytes (the "Trojan Source" attack vector).

4. Control Character Pollution:
   Null bytes (\\x00), Bell alerts (\\x07), Backspaces (\\x08), and Form Feeds (\\x0c)
   corrupt line-oriented log processors and cause unexpected crashes.

This module guarantees that any input string is safely transformed into an unambiguous,
single-line, non-executable, human- and machine-readable log payload.
"""

from __future__ import annotations

# re provides regular expressions used to find escape sequences.
import re
from typing import Pattern

# ==============================================================================
# REGULAR EXPRESSIONS FOR ANSI ESCAPE AND TERMINAL SEQUENCE SCRUBBING
# ==============================================================================
# Regex matching ANSI escape sequences:
# 1. Standard CSI (Control Sequence Introducer): ESC [ ... <final_byte>
# 2. OSC (Operating System Command): ESC ] ... BEL or ESC \
# 3. 2-character escape codes: ESC <char>
# 4. DCS (Device Control String), PM (Privacy Message), APC (Application Program Command)
ANSI_ESCAPE_RE: Pattern[str] = re.compile(
    r"""
    \x1B                     # ASCII ESC character (0x1B or \033)
    (?:
        \[                   # Control Sequence Introducer (CSI)
        [0-?]*               # Parameter bytes (0x30-0x3F: '0'-'?')
        [ -/]*               # Intermediate bytes (0x20-0x2F: ' '-'/')
        [@-~]                # Final byte (0x40-0x7E: '@'-'~')
    |
        \]                   # Operating System Command (OSC)
        [^\x07\x1B]*         # Content until BEL or ESC
        (?:\x07|\x1B\\)?     # Terminated by BEL (\x07) or ST (ESC \)
    |
        [@-Z\\-_]            # 2-character escape sequences (ESC followed by @ to _)
    )
    """,
    re.VERBOSE,
)

# Regex matching Unicode Bidirectional (Bidi) override and embedding code points:
# U+202A (LRE), U+202B (RLE), U+202C (PDF), U+202D (LRO), U+202E (RLO)
# U+2066 (LRI), U+2067 (RLI), U+2068 (FSI), U+2069 (PDI)
BIDI_OVERRIDES_RE: Pattern[str] = re.compile(
    r"[\u202A-\u202E\u2066-\u2069]"
)


class LogSanitizer:
    """
    Production-grade sanitizer providing defensive neutralization against CWE-117.
    """

    def __init__(
        self,
        strip_ansi: bool = True,
        escape_newlines: bool = True,
        strip_bidi: bool = True,
        preserve_tabs: bool = True,
        max_message_length: int = 65536,
    ) -> None:
        """
        Configure the sanitization engine.

        Parameters:
            strip_ansi: If True, completely strips all ANSI escape codes.
            escape_newlines: If True, converts '\\r' to '\\\\r' and '\\n' to '\\\\n'
                             to prevent log line splitting. If False, newlines are stripped.
            strip_bidi: If True, strips Unicode bidirectional override characters.
            preserve_tabs: If True, preserves horizontal tabs ('\\t'); if False, escapes them.
            max_message_length: Bounds maximum payload size to prevent memory exhaustion / DoS.
        """
        # Remember each option so sanitize() can follow it later.
        self.strip_ansi = strip_ansi
        self.escape_newlines = escape_newlines
        self.strip_bidi = strip_bidi
        self.preserve_tabs = preserve_tabs
        self.max_message_length = max_message_length

    def sanitize(self, raw_input: str) -> str:
        """
        Execute full sanitization pipeline on raw incoming log text.

        Pipeline steps:
          1. Truncate to maximum permissible length (DoS defense).
          2. Strip ANSI escape sequences (terminal injection defense).
          3. Strip Unicode Bidirectional overrides (Trojan Source defense).
          4. Escape or replace carriage returns and newlines (line splitting defense).
          5. Escape non-printable control characters (0x00-0x1F, 0x7F).

        Parameters:
            raw_input: Untrusted string input.

        Returns:
            Sanitized, single-line safe text string.
        """
        # Nothing to clean: empty or None input becomes an empty string.
        if not raw_input:
            return ""

        # Step 1: Enforce maximum message length constraint
        # Cut the text to the maximum length so huge inputs cannot use up memory.
        text = str(raw_input)[: self.max_message_length]

        # Step 2: Strip ANSI escape sequences (CSI, OSC, etc.)
        if self.strip_ansi:
            # Replace every matched escape sequence with nothing (delete it).
            text = ANSI_ESCAPE_RE.sub("", text)

        # Step 3: Strip Unicode Bidirectional (Bidi) spoofing characters
        if self.strip_bidi:
            # Delete direction-override characters that could disguise text.
            text = BIDI_OVERRIDES_RE.sub("", text)

        # Step 4: Handle line-splitting characters (\r and \n)
        if self.escape_newlines:
            # Replace carriage return and line feed with literal representations
            text = text.replace("\r\n", "\\n").replace("\r", "\\r").replace("\n", "\\n")
        else:
            # Replace newlines with single spaces to keep output continuous
            text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")

        # Step 5: Sanitize low-order ASCII control characters (0x00 - 0x1F) and DEL (0x7F)
        # Tab (\t) can optionally be preserved for structured TSV or tabular logs.
        # Walk the text one character at a time and build the cleaned result.
        cleaned_chars = []
        for ch in text:
            # ord() gives the numeric code of the character so we can test its range.
            code = ord(ch)
            if code == 9:  # Horizontal Tab (\t)
                if self.preserve_tabs:
                    cleaned_chars.append("\t")
                else:
                    cleaned_chars.append("\\t")
            elif code < 32 or code == 127:
                # Replace non-printable control char with hex escape sequence (e.g. \x00, \x07)
                cleaned_chars.append(f"\\x{code:02x}")
            else:
                cleaned_chars.append(ch)

        # Glue the cleaned characters back into one string.
        return "".join(cleaned_chars)


# Default module-level singleton instance for zero-allocation reuse
# Built once at import time and reused so we do not create a new object per message.
_DEFAULT_SANITIZER = LogSanitizer()


def sanitize_log_message(
    message: str,
    strip_ansi: bool = True,
    escape_newlines: bool = True,
    preserve_tabs: bool = True,
) -> str:
    """
    Convenience functional interface to sanitize a log message string.

    Parameters:
        message: Raw untrusted message string.
        strip_ansi: Remove ANSI CSI/OSC escape sequences.
        escape_newlines: Convert newlines into visible '\\n' tokens.
        preserve_tabs: Retain horizontal tab characters without hex escaping.

    Returns:
        Sanitized, line-safe log string.
    """
    # Default settings: reuse the shared sanitizer.
    if strip_ansi and escape_newlines and preserve_tabs:
        return _DEFAULT_SANITIZER.sanitize(message)
    
    # Non-default settings: make a one-off sanitizer with the requested options.
    custom = LogSanitizer(
        strip_ansi=strip_ansi,
        escape_newlines=escape_newlines,
        preserve_tabs=preserve_tabs,
    )
    return custom.sanitize(message)
