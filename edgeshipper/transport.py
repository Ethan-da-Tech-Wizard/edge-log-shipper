# ==============================================================================
# Program: transport.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Resilient syslog transport client for TCP and UDP protocols featuring
#          TCP_NODELAY optimization, SO_KEEPALIVE, and exponential backoff reconnection.
# ==============================================================================
"""
Resilient Syslog Transport Client for TCP and UDP with Exponential Backoff.

================================================================================
LOW-LEVEL NETWORK & SOCKET PROGRAMMING CONCEPTS:
================================================================================
1. The Nagle Algorithm & TCP_NODELAY:
   By default, the BSD/POSIX socket implementation enables the Nagle algorithm
   (RFC 896). Nagle's algorithm delays the transmission of small outgoing packets
   if unacknowledged data is outstanding on the TCP connection, coalescing them
   until a full Maximum Segment Size (MSS) packet can be dispatched.
   In log shipping, this causes disastrous artificial latency spikes (often 40ms to
   200ms) on each emitted line while the socket engine waits for ACKs.
   Setting `TCP_NODELAY = 1` immediately disables Nagle's algorithm, ensuring each
   log frame is packetized and sent on the wire instantaneously.

2. TCP Keepalives & Half-Open Socket Detection:
   In distributed edge computing (especially across VPN tunnels like WireGuard or
   cellular networks), a network connection can fail silently without sending a
   TCP FIN or RST packet (e.g. an intermediate NAT router rebooting or dropouts).
   Without keepalives, a client socket could remain blocked or believing it is
   connected for hours.
   Enabling `SO_KEEPALIVE` instructs the Linux TCP stack to periodically transmit
   probe packets to the remote peer:
     - TCP_KEEPIDLE: Idle time before starting probes (e.g. 30s).
     - TCP_KEEPINTVL: Interval between probes (e.g. 5s).
     - TCP_KEEPCNT: Max failed probes before tearing down the connection (e.g. 3).

3. Socket Timeouts:
   By default, POSIX sockets block indefinitely. If a remote syslog aggregator hangs,
   a blocking `connect()` or `send()` will hang the client process forever.
   We enforce explicit timeouts on both connection establishment and buffer writes.

4. Exponential Backoff with Full Randomized Jitter:
   When a central log collector experiences downtime and restarts, hundreds or thousands
   of edge log shippers simultaneously attempt reconnection. If they retry at deterministic
   intervals, they create a devastating "Thundering Herd" DDoS against the syslog server.
   We implement Full Jitter backoff (pioneered by AWS Architecture):
       sleep_interval = random.uniform(0, min(max_backoff, base * (multiplier ** attempt)))
   This decorrelates client retry cycles across the entire fleet.

5. UDP vs TCP Delivery Semantics:
   - UDP (User Datagram Protocol): Fire-and-forget, connectionless, zero handshake overhead.
     Subject to packet loss and truncation if datagram exceeds path MTU (typically 1024 or 1472 bytes).
   - TCP (Transmission Control Protocol): Connection-oriented, stream-oriented, guaranteed in-order
     delivery, backpressure-aware via flow control windows.
"""

from __future__ import annotations

import random
import socket
import time
from typing import List, Optional, Tuple

from edgeshipper.models import ShipperConfig


class SyslogTransport:
    """
    High-resilience network client supporting TCP and UDP syslog delivery.
    """

    def __init__(self, config: ShipperConfig) -> None:
        """
        Initialize the transport engine with configuration parameters.

        Parameters:
            config: ShipperConfig instance specifying target host, port, protocol, and timeouts.
        """
        self.config = config
        self._sock: Optional[socket.socket] = None
        self._is_connected: bool = False
        self._reconnect_attempts: int = 0
        self._last_connect_failure: float = 0.0

    @property
    def is_connected(self) -> bool:
        """Return current logical connection status."""
        return self._is_connected and (self._sock is not None)

    def _configure_tcp_socket_options(self, sock: socket.socket) -> None:
        """
        Apply low-level kernel socket options for optimal log shipping latency and health checks.
        """
        # 1. Disable Nagle's Algorithm (TCP_NODELAY = 1)
        # Prevents kernel buffering of small log payloads, eliminating 40-200ms delayed ACK latency.
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        # 2. Enable TCP Keepalives (SO_KEEPALIVE = 1)
        # Allows kernel to detect dead half-open connections across firewalls/WireGuard tunnels.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

        # 3. Configure OS-specific Keepalive probe parameters if running on Linux
        # TCP_KEEPIDLE: Seconds the connection must sit idle before OS sends keepalive probes.
        # TCP_KEEPINTVL: Interval in seconds between individual keepalive probes.
        # TCP_KEEPCNT: Number of unanswered probes before socket is pronounced dead.
        if hasattr(socket, "TCP_KEEPIDLE"):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            except OSError:
                pass
        if hasattr(socket, "TCP_KEEPINTVL"):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            except OSError:
                pass
        if hasattr(socket, "TCP_KEEPCNT"):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except OSError:
                pass

    # Step 1: Establish socket connection with configured timeout and socket options
    def connect(self) -> bool:
        """
        Establish transport connection to upstream syslog collector.

        For TCP: Initiates three-way handshake with configurable timeout.
        For UDP: Prepares datagram socket (binds local endpoint).

        Returns:
            True if connection established successfully, False on failure.
        """
        self.close()

        target = (self.config.target_host, self.config.target_port)

        sock: Optional[socket.socket] = None
        try:
            if self.config.protocol == "tcp":
                # Create TCP stream socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.connect_timeout)

                # Connect to remote peer
                sock.connect(target)

                # Apply performance socket options
                self._configure_tcp_socket_options(sock)

                # Set socket write timeout for subsequent transmission calls
                sock.settimeout(self.config.send_timeout)

                self._sock = sock
                self._is_connected = True
                self._reconnect_attempts = 0
                return True

            elif self.config.protocol == "udp":
                # Create UDP datagram socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.config.send_timeout)
                # For UDP, socket.connect() associates the socket with the remote address,
                # allowing use of send() instead of sendto() and filtering incoming ICMP errors.
                sock.connect(target)

                self._sock = sock
                self._is_connected = True
                self._reconnect_attempts = 0
                return True

        except (socket.error, OSError) as exc:
            self._is_connected = False
            self._last_connect_failure = time.time()
            self._reconnect_attempts += 1
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self.close()
            return False

        return False

    def calculate_backoff(self) -> float:
        """
        Calculate sleep delay using Exponential Backoff with Full Randomized Jitter.

        Formula:
            ceiling = min(max_backoff, initial * (multiplier ** attempts))
            sleep_duration = random.uniform(0, ceiling)

        Returns:
            Float number of seconds to sleep before retry.
        """
        base = self.config.reconnect_backoff_initial
        mult = self.config.reconnect_backoff_multiplier
        cap = self.config.reconnect_backoff_max
        attempt = min(self._reconnect_attempts, 10)  # Bound power to prevent float overflow

        ceiling = min(cap, base * (mult ** attempt))
        return random.uniform(0.1, max(0.2, ceiling))

    def send_bytes(self, payload: bytes) -> bool:
        """
        Transmit raw bytes to the destination syslog receiver.

        For TCP: Uses sendall() to guarantee complete delivery across partial writes.
        For UDP: Transmits single datagram packet.

        Parameters:
            payload: Formatted wire bytes (including framing).

        Returns:
            True if transmission succeeded, False if socket error occurred.
        """
        if not self._is_connected or self._sock is None:
            if not self.connect():
                return False

        try:
            if self._sock is None:
                return False
            # sendall() continues writing until all bytes in payload are sent or an error occurs
            self._sock.sendall(payload)
            return True
        except (socket.error, OSError):
            # Broken pipe (EPIPE), connection reset by peer (ECONNRESET), or write timeout
            self.close()
            return False

    def send_batch(self, payloads: List[bytes]) -> Tuple[int, List[bytes]]:
        """
        Transmit a batch of byte payloads in sequence.

        Parameters:
            payloads: List of byte arrays to send.

        Returns:
            Tuple of (sent_count, list_of_failed_payloads).
        """
        sent_count = 0
        for i, payload in enumerate(payloads):
            success = self.send_bytes(payload)
            if success:
                sent_count += 1
            else:
                # On first transmission failure, return unsent remainder for spooling
                return sent_count, payloads[i:]
        return sent_count, []

    def close(self) -> None:
        """Cleanly tear down and close open socket handles."""
        self._is_connected = False
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
