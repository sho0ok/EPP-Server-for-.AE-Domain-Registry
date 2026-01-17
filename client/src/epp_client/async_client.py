"""
Async EPP Client

Asynchronous EPP client for high-performance operations.
"""

import asyncio
import logging
import secrets
import ssl
import string
from typing import List, Optional, Union

from epp_client.exceptions import (
    EPPAuthenticationError,
    EPPCommandError,
    EPPConnectionError,
    EPPObjectExists,
    EPPObjectNotFound,
)
from epp_client.framing import decode_frame_header, encode_frame, MAX_FRAME_SIZE
from epp_client.models import (
    AEEligibility,
    ContactCheckResult,
    ContactCreate,
    ContactCreateResult,
    ContactInfo,
    ContactUpdate,
    DomainCheckResult,
    DomainCreate,
    DomainCreateResult,
    DomainInfo,
    DomainRenewResult,
    DomainTransferResult,
    DomainUpdate,
    EPPResponse,
    Greeting,
    HostCheckResult,
    HostCreate,
    HostCreateResult,
    HostInfo,
    HostUpdate,
    PollMessage,
)
from epp_client.xml_builder import XMLBuilder
from epp_client.xml_parser import XMLParser

logger = logging.getLogger("epp.async_client")


class AsyncEPPClient:
    """
    Asynchronous EPP client for domain registry operations.

    Provides the same API as EPPClient but with async/await support
    for non-blocking I/O operations.

    Example:
        async with AsyncEPPClient(
            host="epp.registry.ae",
            port=700,
            cert_file="client.crt",
            key_file="client.key"
        ) as client:
            await client.login("registrar1", "password123")
            result = await client.domain_check(["example.ae", "test.ae"])
            await client.logout()
    """

    def __init__(
        self,
        host: str,
        port: int = 700,
        cert_file: str = None,
        key_file: str = None,
        ca_file: str = None,
        timeout: float = 30.0,
        verify_server: bool = True,
        client_id: str = None,
        password: str = None,
        auto_login: bool = False,
    ):
        """
        Initialize async EPP client.

        Args:
            host: EPP server hostname
            port: EPP server port (default: 700)
            cert_file: Path to client certificate (PEM)
            key_file: Path to client private key (PEM)
            ca_file: Path to CA certificate(s) (PEM)
            timeout: Connection timeout in seconds
            verify_server: Whether to verify server certificate
            client_id: Client/registrar ID for auto-login
            password: Password for auto-login
            auto_login: If True, automatically login on connect
        """
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.timeout = timeout
        self.verify_server = verify_server

        self._client_id = client_id
        self._password = password
        self._auto_login = auto_login

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False
        self._logged_in = False
        self._greeting: Optional[Greeting] = None
        self._cl_trid_counter = 0
        self._lock = asyncio.Lock()

    @property
    def is_connected(self) -> bool:
        """Check if connected to server."""
        return self._connected and self._writer is not None

    @property
    def is_logged_in(self) -> bool:
        """Check if logged in."""
        return self._logged_in

    @property
    def greeting(self) -> Optional[Greeting]:
        """Get server greeting received on connect."""
        return self._greeting

    def _generate_cl_trid(self) -> str:
        """Generate unique client transaction ID."""
        self._cl_trid_counter += 1
        return f"ASYNC-{self._cl_trid_counter:06d}"

    def _generate_auth_info(self, length: int = 16) -> str:
        """Generate random auth info password."""
        chars = string.ascii_letters + string.digits + "!@#$%"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for connection."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.verify_server:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
        else:
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False

        if self.ca_file:
            context.load_verify_locations(self.ca_file)
        else:
            context.load_default_certs()

        if self.cert_file and self.key_file:
            context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        elif self.cert_file:
            context.load_cert_chain(certfile=self.cert_file)

        return context

    async def _read_frame(self) -> bytes:
        """Read a complete EPP frame."""
        # Read 4-byte header
        header = await asyncio.wait_for(
            self._reader.readexactly(4),
            timeout=self.timeout
        )

        total_length = decode_frame_header(header)
        payload_length = total_length - 4

        if payload_length == 0:
            return b""

        # Read payload
        payload = await asyncio.wait_for(
            self._reader.readexactly(payload_length),
            timeout=self.timeout
        )

        return payload

    async def _write_frame(self, data: bytes) -> None:
        """Write a complete EPP frame."""
        frame = encode_frame(data)
        self._writer.write(frame)
        await self._writer.drain()

    async def _send_command(self, xml: bytes) -> bytes:
        """Send command and receive response."""
        if not self.is_connected:
            raise EPPConnectionError("Not connected to server")

        async with self._lock:
            await self._write_frame(xml)
            return await self._read_frame()

    def _check_response(self, response: EPPResponse) -> EPPResponse:
        """Check response for errors."""
        if response.success:
            return response

        code = response.code
        message = response.message

        if code in (2200, 2201, 2202):
            raise EPPAuthenticationError(message, code)
        if code == 2303:
            raise EPPObjectNotFound(message, code)
        if code == 2302:
            raise EPPObjectExists(message, code)

        raise EPPCommandError(message, code)

    # =========================================================================
    # Connection Management
    # =========================================================================

    async def connect(self) -> Greeting:
        """Connect to EPP server."""
        if self._connected:
            raise EPPConnectionError("Already connected")

        try:
            ssl_context = self._create_ssl_context()

            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host,
                    self.port,
                    ssl=ssl_context,
                    server_hostname=self.host,
                ),
                timeout=self.timeout
            )

            self._connected = True

            # Read greeting
            greeting_xml = await self._read_frame()
            self._greeting = XMLParser.parse_greeting(greeting_xml)

            logger.info(f"Connected to {self._greeting.server_id}")

            # Auto-login if configured
            if self._auto_login and self._client_id and self._password:
                await self.login(self._client_id, self._password)

            return self._greeting

        except asyncio.TimeoutError:
            await self._cleanup()
            raise EPPConnectionError(f"Connection timeout to {self.host}:{self.port}")
        except ssl.SSLError as e:
            await self._cleanup()
            raise EPPConnectionError(f"TLS error: {e}")
        except Exception as e:
            await self._cleanup()
            raise EPPConnectionError(f"Connection failed: {e}")

    async def disconnect(self) -> None:
        """Disconnect from EPP server."""
        if self._logged_in:
            try:
                await self.logout()
            except Exception as e:
                logger.warning(f"Logout failed during disconnect: {e}")

        await self._cleanup()

    async def _cleanup(self) -> None:
        """Clean up connection resources."""
        self._connected = False
        self._logged_in = False

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
        return False

    # =========================================================================
    # Session Commands
    # =========================================================================

    async def hello(self) -> Greeting:
        """Send hello command."""
        xml = XMLBuilder.build_hello()
        response_xml = await self._send_command(xml)
        return XMLParser.parse_greeting(response_xml)

    async def login(
        self,
        client_id: str,
        password: str,
        new_password: str = None,
        version: str = "1.0",
        lang: str = "en",
    ) -> EPPResponse:
        """Login to EPP server."""
        obj_uris = []
        ext_uris = []

        if self._greeting:
            obj_uris = self._greeting.obj_uris
            ext_uris = self._greeting.ext_uris

        xml = XMLBuilder.build_login(
            client_id=client_id,
            password=password,
            new_password=new_password,
            version=version,
            lang=lang,
            obj_uris=obj_uris,
            ext_uris=ext_uris,
            cl_trid=self._generate_cl_trid(),
        )

        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        self._logged_in = True
        self._client_id = client_id

        logger.info(f"Logged in as {client_id}")
        return response

    async def logout(self) -> EPPResponse:
        """Logout from EPP server."""
        xml = XMLBuilder.build_logout(cl_trid=self._generate_cl_trid())
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._logged_in = False
        logger.info("Logged out")

        return response

    # =========================================================================
    # Domain Commands
    # =========================================================================

    async def domain_check(self, names: Union[str, List[str]]) -> DomainCheckResult:
        """Check domain availability."""
        if isinstance(names, str):
            names = [names]

        xml = XMLBuilder.build_domain_check(
            names=names,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_check(response_xml)

    async def domain_info(
        self,
        name: str,
        auth_info: str = None,
        hosts: str = "all",
    ) -> DomainInfo:
        """Get domain information."""
        xml = XMLBuilder.build_domain_info(
            name=name,
            auth_info=auth_info,
            hosts=hosts,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_info(response_xml)

    async def domain_create(
        self,
        name: str,
        registrant: str,
        period: int = 1,
        period_unit: str = "y",
        admin: str = None,
        tech: str = None,
        billing: str = None,
        nameservers: List[str] = None,
        auth_info: str = None,
        ae_eligibility: AEEligibility = None,
    ) -> DomainCreateResult:
        """Create a domain.

        Args:
            name: Domain name
            registrant: Registrant contact ID
            period: Registration period (default: 1)
            period_unit: Period unit - y=year, m=month (default: y)
            admin: Admin contact ID
            tech: Tech contact ID
            billing: Billing contact ID
            nameservers: List of nameserver hostnames
            auth_info: Auth info (auto-generated if not provided)
            ae_eligibility: AE eligibility extension data for restricted zones
        """
        if auth_info is None:
            auth_info = self._generate_auth_info()

        create_data = DomainCreate(
            name=name,
            registrant=registrant,
            period=period,
            period_unit=period_unit,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=nameservers or [],
            auth_info=auth_info,
            ae_eligibility=ae_eligibility,
        )

        xml = XMLBuilder.build_domain_create(
            create_data=create_data,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_create(response_xml)

    async def domain_delete(self, name: str) -> EPPResponse:
        """Delete a domain."""
        xml = XMLBuilder.build_domain_delete(
            name=name,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    async def domain_renew(
        self,
        name: str,
        cur_exp_date: str,
        period: int = 1,
        period_unit: str = "y",
    ) -> DomainRenewResult:
        """Renew a domain."""
        xml = XMLBuilder.build_domain_renew(
            name=name,
            cur_exp_date=cur_exp_date,
            period=period,
            period_unit=period_unit,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_renew(response_xml)

    async def domain_transfer_request(
        self,
        name: str,
        auth_info: str,
        period: int = None,
        period_unit: str = "y",
    ) -> DomainTransferResult:
        """Request domain transfer."""
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="request",
            auth_info=auth_info,
            period=period,
            period_unit=period_unit,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_transfer(response_xml)

    async def domain_update(
        self,
        name: str,
        add_ns: List[str] = None,
        rem_ns: List[str] = None,
        add_status: List[str] = None,
        rem_status: List[str] = None,
        new_registrant: str = None,
        new_auth_info: str = None,
    ) -> EPPResponse:
        """Update a domain."""
        update_data = DomainUpdate(
            name=name,
            add_ns=add_ns or [],
            rem_ns=rem_ns or [],
            add_status=add_status or [],
            rem_status=rem_status or [],
            new_registrant=new_registrant,
            new_auth_info=new_auth_info,
        )

        xml = XMLBuilder.build_domain_update(
            update_data=update_data,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Contact Commands
    # =========================================================================

    async def contact_check(self, ids: Union[str, List[str]]) -> ContactCheckResult:
        """Check contact availability."""
        if isinstance(ids, str):
            ids = [ids]

        xml = XMLBuilder.build_contact_check(
            ids=ids,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_check(response_xml)

    async def contact_info(self, id: str, auth_info: str = None) -> ContactInfo:
        """Get contact information."""
        xml = XMLBuilder.build_contact_info(
            id=id,
            auth_info=auth_info,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_info(response_xml)

    async def contact_create(
        self,
        id: str,
        name: str,
        email: str,
        city: str,
        country_code: str,
        org: str = None,
        street: List[str] = None,
        state: str = None,
        postal_code: str = None,
        voice: str = None,
        fax: str = None,
        auth_info: str = None,
        postal_type: str = "int",
    ) -> ContactCreateResult:
        """Create a contact."""
        from epp_client.models import PostalInfo

        if auth_info is None:
            auth_info = self._generate_auth_info()

        postal_info = PostalInfo(
            name=name,
            city=city,
            cc=country_code,
            type=postal_type,
            org=org,
            street=street or [],
            sp=state,
            pc=postal_code,
        )

        create_data = ContactCreate(
            id=id,
            email=email,
            postal_info=postal_info,
            voice=voice,
            fax=fax,
            auth_info=auth_info,
        )

        xml = XMLBuilder.build_contact_create(
            create_data=create_data,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_create(response_xml)

    async def contact_delete(self, id: str) -> EPPResponse:
        """Delete a contact."""
        xml = XMLBuilder.build_contact_delete(
            id=id,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    async def contact_update(
        self,
        id: str,
        add_status: List[str] = None,
        rem_status: List[str] = None,
        new_email: str = None,
        new_voice: str = None,
        new_fax: str = None,
        new_auth_info: str = None,
    ) -> EPPResponse:
        """Update a contact."""
        update_data = ContactUpdate(
            id=id,
            add_status=add_status or [],
            rem_status=rem_status or [],
            new_email=new_email,
            new_voice=new_voice,
            new_fax=new_fax,
            new_auth_info=new_auth_info,
        )

        xml = XMLBuilder.build_contact_update(
            update_data=update_data,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Host Commands
    # =========================================================================

    async def host_check(self, names: Union[str, List[str]]) -> HostCheckResult:
        """Check host availability."""
        if isinstance(names, str):
            names = [names]

        xml = XMLBuilder.build_host_check(
            names=names,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_check(response_xml)

    async def host_info(self, name: str) -> HostInfo:
        """Get host information."""
        xml = XMLBuilder.build_host_info(
            name=name,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_info(response_xml)

    async def host_create(
        self,
        name: str,
        ipv4: List[str] = None,
        ipv6: List[str] = None,
    ) -> HostCreateResult:
        """Create a host."""
        from epp_client.models import HostAddress

        addresses = []
        for ip in (ipv4 or []):
            addresses.append(HostAddress(address=ip, ip_version="v4"))
        for ip in (ipv6 or []):
            addresses.append(HostAddress(address=ip, ip_version="v6"))

        create_data = HostCreate(
            name=name,
            addresses=addresses,
        )

        xml = XMLBuilder.build_host_create(
            create_data=create_data,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_create(response_xml)

    async def host_delete(self, name: str) -> EPPResponse:
        """Delete a host."""
        xml = XMLBuilder.build_host_delete(
            name=name,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    async def host_update(
        self,
        name: str,
        add_ipv4: List[str] = None,
        add_ipv6: List[str] = None,
        rem_ipv4: List[str] = None,
        rem_ipv6: List[str] = None,
        add_status: List[str] = None,
        rem_status: List[str] = None,
        new_name: str = None,
    ) -> EPPResponse:
        """Update a host."""
        from epp_client.models import HostAddress

        add_addresses = []
        for ip in (add_ipv4 or []):
            add_addresses.append(HostAddress(address=ip, ip_version="v4"))
        for ip in (add_ipv6 or []):
            add_addresses.append(HostAddress(address=ip, ip_version="v6"))

        rem_addresses = []
        for ip in (rem_ipv4 or []):
            rem_addresses.append(HostAddress(address=ip, ip_version="v4"))
        for ip in (rem_ipv6 or []):
            rem_addresses.append(HostAddress(address=ip, ip_version="v6"))

        update_data = HostUpdate(
            name=name,
            add_addresses=add_addresses,
            rem_addresses=rem_addresses,
            add_status=add_status or [],
            rem_status=rem_status or [],
            new_name=new_name,
        )

        xml = XMLBuilder.build_host_update(
            update_data=update_data,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Poll Commands
    # =========================================================================

    async def poll_request(self) -> Optional[PollMessage]:
        """Request next poll message."""
        xml = XMLBuilder.build_poll_request(cl_trid=self._generate_cl_trid())
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        if response.code == 1301:
            return None

        self._check_response(response)
        return XMLParser.parse_poll_message(response_xml)

    async def poll_ack(self, msg_id: str) -> EPPResponse:
        """Acknowledge poll message."""
        xml = XMLBuilder.build_poll_ack(
            msg_id=msg_id,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = await self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)
