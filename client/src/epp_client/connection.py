"""
EPP Connection

Handles TLS connection to EPP server with client certificate authentication.
"""

import logging
import socket
import ssl
from typing import Optional

from epp_client.exceptions import EPPConnectionError
from epp_client.framing import FrameReader, FrameWriter, encode_frame

logger = logging.getLogger("epp.connection")


class EPPConnection:
    """
    TLS connection to EPP server.

    Handles:
    - TLS 1.2+ connection with client certificate
    - Connection lifecycle (connect, disconnect)
    - Frame-based I/O
    - Timeout handling
    """

    def __init__(
        self,
        host: str,
        port: int = 700,
        cert_file: str = None,
        key_file: str = None,
        ca_file: str = None,
        timeout: int = 30,
        verify_server: bool = True,
    ):
        """
        Initialize EPP connection.

        Args:
            host: EPP server hostname
            port: EPP server port (default: 700)
            cert_file: Path to client certificate (PEM)
            key_file: Path to client private key (PEM)
            ca_file: Path to CA certificate(s) (PEM)
            timeout: Connection timeout in seconds
            verify_server: Whether to verify server certificate
        """
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.timeout = timeout
        self.verify_server = verify_server

        self._socket: Optional[socket.socket] = None
        self._ssl_socket: Optional[ssl.SSLSocket] = None
        self._frame_reader: Optional[FrameReader] = None
        self._frame_writer: Optional[FrameWriter] = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Check if connected to server."""
        return self._connected and self._ssl_socket is not None

    def connect(self) -> None:
        """
        Establish TLS connection to EPP server.

        Raises:
            EPPConnectionError: If connection fails
        """
        if self._connected:
            raise EPPConnectionError("Already connected")

        try:
            # Create SSL context
            context = self._create_ssl_context()

            # Create socket
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)

            # Wrap with TLS
            self._ssl_socket = context.wrap_socket(
                self._socket,
                server_hostname=self.host
            )

            # Connect
            logger.debug(f"Connecting to {self.host}:{self.port}")
            self._ssl_socket.connect((self.host, self.port))

            # Setup frame handlers
            self._frame_reader = FrameReader(self._ssl_socket.recv)
            self._frame_writer = FrameWriter(self._ssl_socket.send)

            self._connected = True
            logger.info(f"Connected to {self.host}:{self.port}")

            # Log TLS info
            cipher = self._ssl_socket.cipher()
            if cipher:
                logger.debug(f"TLS cipher: {cipher[0]}, version: {cipher[1]}")

        except ssl.SSLError as e:
            self._cleanup()
            raise EPPConnectionError(f"TLS error: {e}")
        except socket.timeout:
            self._cleanup()
            raise EPPConnectionError(f"Connection timeout to {self.host}:{self.port}")
        except socket.error as e:
            self._cleanup()
            raise EPPConnectionError(f"Socket error: {e}")
        except Exception as e:
            self._cleanup()
            raise EPPConnectionError(f"Connection failed: {e}")

    def disconnect(self) -> None:
        """Close connection to EPP server."""
        if not self._connected:
            return

        logger.debug(f"Disconnecting from {self.host}:{self.port}")
        self._cleanup()
        logger.info(f"Disconnected from {self.host}:{self.port}")

    def send(self, data: bytes) -> None:
        """
        Send EPP frame to server.

        Args:
            data: XML data to send

        Raises:
            EPPConnectionError: If send fails
        """
        if not self.is_connected:
            raise EPPConnectionError("Not connected")

        try:
            self._frame_writer.write_frame(data)
            logger.debug(f"Sent {len(data)} bytes")
        except Exception as e:
            raise EPPConnectionError(f"Send failed: {e}")

    def receive(self) -> bytes:
        """
        Receive EPP frame from server.

        Returns:
            XML data received

        Raises:
            EPPConnectionError: If receive fails
        """
        if not self.is_connected:
            raise EPPConnectionError("Not connected")

        try:
            data = self._frame_reader.read_frame()
            logger.debug(f"Received {len(data)} bytes")
            return data
        except socket.timeout:
            raise EPPConnectionError("Read timeout")
        except Exception as e:
            raise EPPConnectionError(f"Receive failed: {e}")

    def send_and_receive(self, data: bytes) -> bytes:
        """
        Send request and receive response.

        Args:
            data: XML request data

        Returns:
            XML response data

        Raises:
            EPPConnectionError: If operation fails
        """
        self.send(data)
        return self.receive()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context for EPP connection.

        Returns:
            Configured SSL context
        """
        # Create context with TLS 1.2 minimum
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Set verification mode
        if self.verify_server:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
        else:
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False

        # Load CA certificates
        if self.ca_file:
            context.load_verify_locations(self.ca_file)
        else:
            # Use system default CA certificates
            context.load_default_certs()

        # Load client certificate and key
        if self.cert_file and self.key_file:
            context.load_cert_chain(
                certfile=self.cert_file,
                keyfile=self.key_file
            )
        elif self.cert_file:
            # Cert and key in same file
            context.load_cert_chain(certfile=self.cert_file)

        # Security settings
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1

        return context

    def _cleanup(self) -> None:
        """Clean up connection resources."""
        self._connected = False
        self._frame_reader = None
        self._frame_writer = None

        if self._ssl_socket:
            try:
                self._ssl_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._ssl_socket.close()
            except Exception:
                pass
            self._ssl_socket = None

        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False

    def get_server_certificate(self) -> Optional[dict]:
        """
        Get server certificate info.

        Returns:
            Certificate info dict or None
        """
        if not self._ssl_socket:
            return None
        return self._ssl_socket.getpeercert()

    def get_cipher(self) -> Optional[tuple]:
        """
        Get current cipher info.

        Returns:
            Tuple of (cipher_name, protocol_version, bits) or None
        """
        if not self._ssl_socket:
            return None
        return self._ssl_socket.cipher()
