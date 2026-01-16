"""
TLS Handler for EPP Server

Provides TLS 1.2+ configuration with client certificate verification
for secure EPP connections.
"""

import ssl
import logging
from typing import Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger("epp.tls")


@dataclass
class ClientCertInfo:
    """Information extracted from client certificate"""
    common_name: str
    organization: Optional[str] = None
    country: Optional[str] = None
    serial_number: Optional[str] = None
    issuer_cn: Optional[str] = None


class TLSHandler:
    """
    Manages TLS configuration for EPP server.

    Creates SSL context with:
    - TLS 1.2 minimum version
    - Strong cipher suites
    - Client certificate verification
    - Server certificate and key loading
    """

    # Strong cipher suites for TLS 1.2+
    CIPHER_SUITES = [
        "ECDHE+AESGCM",
        "ECDHE+CHACHA20",
        "DHE+AESGCM",
        "DHE+CHACHA20",
        "ECDH+AESGCM",
        "DH+AESGCM",
        "ECDH+AES",
        "DH+AES",
        "!aNULL",
        "!eNULL",
        "!EXPORT",
        "!DES",
        "!RC4",
        "!3DES",
        "!MD5",
        "!PSK",
    ]

    def __init__(
        self,
        cert_file: str,
        key_file: str,
        ca_file: str,
        min_version: str = "TLSv1.2",
        verify_client: bool = True
    ):
        """
        Initialize TLS handler.

        Args:
            cert_file: Path to server certificate file
            key_file: Path to server private key file
            ca_file: Path to CA bundle for client verification
            min_version: Minimum TLS version (TLSv1.2 or TLSv1.3)
            verify_client: Whether to require client certificates
        """
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.min_version = min_version
        self.verify_client = verify_client
        self._ssl_context: Optional[ssl.SSLContext] = None

    def create_ssl_context(self) -> ssl.SSLContext:
        """
        Create and configure SSL context for the server.

        Returns:
            Configured SSLContext object

        Raises:
            ssl.SSLError: If certificate files cannot be loaded
            FileNotFoundError: If certificate files don't exist
        """
        # Create context for server-side TLS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Set minimum TLS version
        if self.min_version == "TLSv1.3":
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable older protocols explicitly
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1

        # Set cipher suites
        cipher_string = ":".join(self.CIPHER_SUITES)
        try:
            context.set_ciphers(cipher_string)
        except ssl.SSLError as e:
            logger.warning(f"Could not set all ciphers, using defaults: {e}")
            context.set_ciphers("HIGH:!aNULL:!MD5")

        # Load server certificate and key
        logger.info(f"Loading server certificate from {self.cert_file}")
        context.load_cert_chain(
            certfile=self.cert_file,
            keyfile=self.key_file
        )

        # Load CA certificates for client verification
        if self.verify_client:
            logger.info(f"Loading CA bundle from {self.ca_file}")
            context.load_verify_locations(cafile=self.ca_file)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_OPTIONAL

        # Additional security options
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        context.options |= ssl.OP_NO_COMPRESSION

        self._ssl_context = context
        logger.info(f"TLS context created with minimum version {self.min_version}")

        return context

    def get_ssl_context(self) -> ssl.SSLContext:
        """
        Get or create SSL context.

        Returns:
            Configured SSLContext object
        """
        if self._ssl_context is None:
            return self.create_ssl_context()
        return self._ssl_context

    @staticmethod
    def extract_client_cert_info(ssl_object: ssl.SSLObject) -> Optional[ClientCertInfo]:
        """
        Extract information from client certificate.

        Args:
            ssl_object: SSL object from established connection

        Returns:
            ClientCertInfo with extracted data, or None if no cert
        """
        try:
            peer_cert = ssl_object.getpeercert()
            if not peer_cert:
                logger.warning("No peer certificate available")
                return None

            # Extract subject fields
            subject = dict(x[0] for x in peer_cert.get("subject", []))
            issuer = dict(x[0] for x in peer_cert.get("issuer", []))

            common_name = subject.get("commonName", "")
            if not common_name:
                logger.warning("Client certificate has no Common Name")
                return None

            cert_info = ClientCertInfo(
                common_name=common_name,
                organization=subject.get("organizationName"),
                country=subject.get("countryName"),
                serial_number=str(peer_cert.get("serialNumber", "")),
                issuer_cn=issuer.get("commonName")
            )

            logger.debug(f"Client certificate: CN={cert_info.common_name}, "
                        f"O={cert_info.organization}")

            return cert_info

        except Exception as e:
            logger.error(f"Error extracting client certificate info: {e}")
            return None

    @staticmethod
    def get_client_ip_from_transport(transport) -> Tuple[str, int]:
        """
        Extract client IP address and port from transport.

        Args:
            transport: asyncio transport object

        Returns:
            Tuple of (ip_address, port)
        """
        try:
            peername = transport.get_extra_info("peername")
            if peername:
                return peername[0], peername[1]
        except Exception as e:
            logger.error(f"Error getting client IP: {e}")
        return "0.0.0.0", 0

    @staticmethod
    def get_ssl_info(transport) -> dict:
        """
        Get SSL connection information from transport.

        Args:
            transport: asyncio transport object

        Returns:
            Dictionary with SSL connection details
        """
        info = {
            "cipher": None,
            "version": None,
            "compression": None,
        }

        try:
            ssl_object = transport.get_extra_info("ssl_object")
            if ssl_object:
                info["cipher"] = ssl_object.cipher()
                info["version"] = ssl_object.version()
                info["compression"] = ssl_object.compression()
        except Exception as e:
            logger.error(f"Error getting SSL info: {e}")

        return info
