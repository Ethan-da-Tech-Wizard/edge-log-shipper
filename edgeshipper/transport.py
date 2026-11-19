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

# Stdlib only: socket for TCP/UDP, random for backoff jitter.
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
        # The socket is created lazily in connect(); None means 'not connected'.
        self._sock: Optional[socket.socket] = None
        self._is_connected: bool = False
        # Consecutive failed connects; drives the exponential backoff exponent and
        # is reset to 0 on success.
        self._reconnect_attempts: int = 0
        self._last_connect_failure: float = 0.0

    @property
    def is_connected(self) -> bool:
        """Return current logical connection status."""
        # Logical state only: a peer that vanished silently is not noticed until
        # the next send fails (keepalives bound how long that can take).
        return self._is_connected and (self._sock is not None)

    def _configure_tcp_socket_options(self, sock: socket.socket) -> None:
        """
        Apply low-level kernel socket options for optimal log shipping latency and health checks.
        """
        # 1. Disable Nagle's Algorithm (TCP_NODELAY = 1)
        # Prevents kernel buffering of small log payloads, eliminating 40-200ms delayed ACK latency.
        try:
            # Each option is applied in its own try/except: failure of an optional
            # tuning knob (unsupported platform/kernel) must never prevent connecting.
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
        # These constants exist on Linux but not on every platform (macOS names the
        # idle option differently), hence the hasattr guards. With the values below a
        # dead peer is detected after roughly 30s idle + 3 probes * 5s = ~45s.
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

    def _connect_first_reachable(self, socktype: int, timeout: float) -> socket.socket:
        """
        Create a socket connected to the configured target, trying every address
        that getaddrinfo returns (IPv4 and/or IPv6) until one succeeds.

        Parameters:
            socktype: socket.SOCK_STREAM (TCP) or socket.SOCK_DGRAM (UDP).
            timeout: Timeout in seconds applied to the socket before connecting.

        Returns:
            A connected socket (caller owns it and must close it).

        Raises:
            OSError: If resolution fails or no address could be connected.
        """
        last_error: Optional[OSError] = None
        for family, stype, proto, _canon, sockaddr in socket.getaddrinfo(
            self.config.target_host, self.config.target_port, type=socktype
        ):
            candidate: Optional[socket.socket] = None
            try:
                candidate = socket.socket(family, stype, proto)
                candidate.settimeout(timeout)
                candidate.connect(sockaddr)
                return candidate
            except OSError as exc:
                last_error = exc
                if candidate is not None:
                    candidate.close()
        raise last_error if last_error is not None else OSError("no address for target host")

    # Step 1: Establish socket connection with configured timeout and socket options
    def connect(self) -> bool:
        """
        Establish transport connection to upstream syslog collector.

        For TCP: Initiates three-way handshake with configurable timeout.
        For UDP: Prepares datagram socket (binds local endpoint).

        Returns:
            True if connection established successfully, False on failure.
        """
        # Always tear down any previous socket first so reconnects never leak
        # file descriptors.
        self.close()

        # Held in a local until fully set up, so a failed connect can close it
        # without touching the previous (already closed) self._sock.
        sock: Optional[socket.socket] = None
        try:
            if self.config.protocol == "tcp":
                # Resolve with getaddrinfo so IPv4, IPv6 and hostnames all work; each
                # candidate address is tried in order until one connects.
                sock = self._connect_first_reachable(socket.SOCK_STREAM, self.config.connect_timeout)

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
                # UDP: connect() sets a default peer and creates no handshake, so it
                # succeeds even if nothing is listening; loss is invisible to us.
                # Associating the peer also lets us use send() and receive ICMP errors.
                sock = self._connect_first_reachable(socket.SOCK_DGRAM, self.config.send_timeout)

                self._sock = sock
                self._is_connected = True
                self._reconnect_attempts = 0
                return True

        # Any connection failure is converted to a False return plus bookkeeping;
        # the shipper reacts by spooling. (socket.error is an alias of OSError.)
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
        # Clamp the exponent so multiplier ** attempt cannot overflow a float after
        # many failures; the result is capped by reconnect_backoff_max anyway.
        attempt = min(self._reconnect_attempts, 10)  # Bound power to prevent float overflow

        ceiling = min(cap, base * (mult ** attempt))
        # Full jitter with a small floor (0.1s) so the delay is never ~0. Note this
        # differs slightly from the docstring formula, which shows a lower bound of 0.
        # This method only computes the delay; callers decide whether to sleep.
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
        # Connect on demand, so callers never need to manage connection state.
        if not self._is_connected or self._sock is None:
            if not self.connect():
                return False

        try:
            if self._sock is None:
                return False
            # sendall() continues writing until all bytes in payload are sent or an error occurs
            # TCP may accept only part of the buffer per call; sendall loops until all
            # bytes are written, the timeout fires, or an error occurs. A timeout
            # mid-write can leave a partial frame on the wire; the connection is closed
            # below so the next send starts on a fresh stream.
            self._sock.sendall(payload)
            return True
        except (socket.error, OSError):
            # Broken pipe (EPIPE), connection reset by peer (ECONNRESET), or write timeout
            # Drop the broken socket so the next send_bytes reconnects from scratch.
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
                # Stop at the first failure (do not skip ahead) so the caller can spool the
                # remainder in its original order.
                return sent_count, payloads[i:]
        return sent_count, []

    def close(self) -> None:
        """Cleanly tear down and close open socket handles."""
        self._is_connected = False
        if self._sock is not None:
            try:
                # shutdown first so the peer sees an orderly close; it raises if the socket
                # is already dead, which is harmless here.
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
