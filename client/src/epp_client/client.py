"""
EPP Client

High-level EPP client for domain registry operations.
"""

import logging
import secrets
import string
from typing import List, Optional, Tuple, Union

from epp_client.connection import EPPConnection
from epp_client.exceptions import (
    EPPAuthenticationError,
    EPPCommandError,
    EPPConnectionError,
    EPPObjectExists,
    EPPObjectNotFound,
)
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
    StatusValue,
)
from epp_client.xml_builder import XMLBuilder
from epp_client.xml_parser import XMLParser

logger = logging.getLogger("epp.client")


class EPPClient:
    """
    High-level EPP client for domain registry operations.

    Provides a clean API for all EPP commands:
    - Session: login, logout, hello
    - Domain: check, info, create, delete, renew, transfer, update
    - Contact: check, info, create, delete, update
    - Host: check, info, create, delete, update
    - Poll: request, acknowledge

    Example:
        client = EPPClient(
            host="epp.registry.ae",
            port=700,
            cert_file="client.crt",
            key_file="client.key",
            ca_file="ca.crt"
        )

        with client:
            client.login("registrar1", "password123")

            # Check domain availability
            result = client.domain_check(["example.ae", "test.ae"])
            for item in result.results:
                print(f"{item.name}: {'available' if item.available else 'taken'}")

            # Create a domain
            response = client.domain_create(
                name="example.ae",
                registrant="contact123",
                admin="admin123",
                tech="tech123"
            )

            client.logout()
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
        client_id: str = None,
        password: str = None,
        auto_login: bool = False,
    ):
        """
        Initialize EPP client.

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
        self._connection = EPPConnection(
            host=host,
            port=port,
            cert_file=cert_file,
            key_file=key_file,
            ca_file=ca_file,
            timeout=timeout,
            verify_server=verify_server,
        )

        self._client_id = client_id
        self._password = password
        self._auto_login = auto_login

        self._greeting: Optional[Greeting] = None
        self._logged_in = False
        self._cl_trid_counter = 0

    @property
    def is_connected(self) -> bool:
        """Check if connected to server."""
        return self._connection.is_connected

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
        return f"CLI-{self._cl_trid_counter:06d}"

    def _generate_auth_info(self, length: int = 16) -> str:
        """Generate random auth info password."""
        chars = string.ascii_letters + string.digits + "!@#$%"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def _send_command(self, xml: bytes) -> bytes:
        """
        Send command and receive response.

        Args:
            xml: XML command

        Returns:
            XML response

        Raises:
            EPPConnectionError: If not connected
        """
        if not self.is_connected:
            raise EPPConnectionError("Not connected to server")

        return self._connection.send_and_receive(xml)

    def _check_response(self, response: EPPResponse) -> EPPResponse:
        """
        Check response for errors and raise appropriate exceptions.

        Args:
            response: EPP response

        Returns:
            Response if successful

        Raises:
            EPPCommandError: If command failed
            EPPObjectNotFound: If object not found
            EPPObjectExists: If object already exists
            EPPAuthenticationError: If authentication failed
        """
        if response.success:
            return response

        code = response.code
        message = response.message

        # Authentication errors
        if code in (2200, 2201, 2202):
            raise EPPAuthenticationError(message, code)

        # Object not found
        if code == 2303:
            raise EPPObjectNotFound(message, code)

        # Object exists
        if code == 2302:
            raise EPPObjectExists(message, code)

        # Generic command error
        raise EPPCommandError(message, code)

    # =========================================================================
    # Connection Management
    # =========================================================================

    def connect(self) -> Greeting:
        """
        Connect to EPP server.

        Returns:
            Server greeting

        Raises:
            EPPConnectionError: If connection fails
        """
        self._connection.connect()

        # Read greeting
        greeting_xml = self._connection.receive()
        self._greeting = XMLParser.parse_greeting(greeting_xml)

        logger.info(f"Connected to {self._greeting.server_id}")

        # Auto-login if configured
        if self._auto_login and self._client_id and self._password:
            self.login(self._client_id, self._password)

        return self._greeting

    def disconnect(self) -> None:
        """Disconnect from EPP server."""
        if self._logged_in:
            try:
                self.logout()
            except Exception as e:
                logger.warning(f"Logout failed during disconnect: {e}")

        self._connection.disconnect()
        self._greeting = None
        self._logged_in = False

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False

    # =========================================================================
    # Session Commands
    # =========================================================================

    def hello(self) -> Greeting:
        """
        Send hello command and receive greeting.

        Returns:
            Server greeting

        Raises:
            EPPConnectionError: If not connected
        """
        xml = XMLBuilder.build_hello()
        response_xml = self._send_command(xml)
        return XMLParser.parse_greeting(response_xml)

    def login(
        self,
        client_id: str,
        password: str,
        new_password: str = None,
        version: str = "1.0",
        lang: str = "en",
    ) -> EPPResponse:
        """
        Login to EPP server.

        Args:
            client_id: Client/registrar ID
            password: Password
            new_password: Optional new password to set
            version: EPP version (default: 1.0)
            lang: Language (default: en)

        Returns:
            EPP response

        Raises:
            EPPAuthenticationError: If login fails
        """
        # Get object URIs from greeting
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

        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        self._logged_in = True
        self._client_id = client_id

        logger.info(f"Logged in as {client_id}")
        return response

    def logout(self) -> EPPResponse:
        """
        Logout from EPP server.

        Returns:
            EPP response

        Raises:
            EPPCommandError: If logout fails
        """
        xml = XMLBuilder.build_logout(cl_trid=self._generate_cl_trid())
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._logged_in = False
        logger.info("Logged out")

        return response

    # =========================================================================
    # Poll Commands
    # =========================================================================

    def poll_request(self) -> Tuple[EPPResponse, Optional[PollMessage]]:
        """
        Request next poll message.

        Returns:
            Tuple of (EPPResponse, PollMessage or None if queue is empty)

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_poll_request(cl_trid=self._generate_cl_trid())
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        # 1301 = no messages
        if response.code == 1301:
            return response, None

        self._check_response(response)
        message = XMLParser.parse_poll_message(response_xml)
        return response, message

    def poll_ack(self, msg_id: str) -> EPPResponse:
        """
        Acknowledge poll message.

        Args:
            msg_id: Message ID to acknowledge

        Returns:
            EPP response

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_poll_ack(
            msg_id=msg_id,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Domain Commands
    # =========================================================================

    def domain_check(self, names: Union[str, List[str]]) -> DomainCheckResult:
        """
        Check domain availability.

        Args:
            names: Domain name(s) to check

        Returns:
            Domain check result

        Raises:
            EPPCommandError: If command fails
        """
        if isinstance(names, str):
            names = [names]

        xml = XMLBuilder.build_domain_check(
            names=names,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_check(response_xml)

    def domain_info(
        self,
        name: str,
        auth_info: str = None,
        hosts: str = "all",
    ) -> DomainInfo:
        """
        Get domain information.

        Args:
            name: Domain name
            auth_info: Optional auth info for transfer
            hosts: Host info to return: all, del, sub, none

        Returns:
            Domain info

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_info(
            name=name,
            auth_info=auth_info,
            hosts=hosts,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_info(response_xml)

    def domain_create(
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
        """
        Create a domain.

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
                           (.co.ae, .gov.ae, .ac.ae, etc.)

        Returns:
            Domain create result

        Raises:
            EPPObjectExists: If domain already exists
            EPPCommandError: If command fails
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
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_create(response_xml)

    def domain_delete(self, name: str) -> EPPResponse:
        """
        Delete a domain.

        Args:
            name: Domain name

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_delete(
            name=name,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_renew(
        self,
        name: str,
        cur_exp_date: str,
        period: int = 1,
        period_unit: str = "y",
    ) -> DomainRenewResult:
        """
        Renew a domain.

        Args:
            name: Domain name
            cur_exp_date: Current expiry date (YYYY-MM-DD)
            period: Renewal period (default: 1)
            period_unit: Period unit - y=year, m=month (default: y)

        Returns:
            Domain renew result

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_renew(
            name=name,
            cur_exp_date=cur_exp_date,
            period=period,
            period_unit=period_unit,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_renew(response_xml)

    def domain_transfer_request(
        self,
        name: str,
        auth_info: str,
        period: int = None,
        period_unit: str = "y",
    ) -> DomainTransferResult:
        """
        Request domain transfer.

        Args:
            name: Domain name
            auth_info: Domain auth info
            period: Optional renewal period
            period_unit: Period unit - y=year, m=month (default: y)

        Returns:
            Domain transfer result

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="request",
            auth_info=auth_info,
            period=period,
            period_unit=period_unit,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_transfer(response_xml)

    def domain_transfer_query(self, name: str) -> DomainTransferResult:
        """
        Query domain transfer status.

        Args:
            name: Domain name

        Returns:
            Domain transfer result

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="query",
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_domain_transfer(response_xml)

    def domain_transfer_approve(self, name: str) -> EPPResponse:
        """
        Approve domain transfer.

        Args:
            name: Domain name

        Returns:
            EPP response

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="approve",
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_transfer_reject(self, name: str) -> EPPResponse:
        """
        Reject domain transfer.

        Args:
            name: Domain name

        Returns:
            EPP response

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="reject",
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_transfer_cancel(self, name: str) -> EPPResponse:
        """
        Cancel domain transfer request.

        Args:
            name: Domain name

        Returns:
            EPP response

        Raises:
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_domain_transfer(
            name=name,
            op="cancel",
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def domain_update(
        self,
        name: str,
        add_ns: List[str] = None,
        rem_ns: List[str] = None,
        add_status: List = None,
        rem_status: List = None,
        new_registrant: str = None,
        new_auth_info: str = None,
    ) -> EPPResponse:
        """
        Update a domain.

        Args:
            name: Domain name
            add_ns: Nameservers to add
            rem_ns: Nameservers to remove
            add_status: Status values to add. Can be strings or StatusValue objects.
                       Example: ["clientHold"] or [StatusValue("clientHold", "Payment pending")]
            rem_status: Status values to remove. Can be strings or StatusValue objects.
            new_registrant: New registrant contact ID
            new_auth_info: New auth info

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If domain not found
            EPPCommandError: If command fails
        """
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
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Contact Commands
    # =========================================================================

    def contact_check(self, ids: Union[str, List[str]]) -> ContactCheckResult:
        """
        Check contact availability.

        Args:
            ids: Contact ID(s) to check

        Returns:
            Contact check result

        Raises:
            EPPCommandError: If command fails
        """
        if isinstance(ids, str):
            ids = [ids]

        xml = XMLBuilder.build_contact_check(
            ids=ids,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_check(response_xml)

    def contact_info(self, id: str, auth_info: str = None) -> ContactInfo:
        """
        Get contact information.

        Args:
            id: Contact ID
            auth_info: Optional auth info

        Returns:
            Contact info

        Raises:
            EPPObjectNotFound: If contact not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_contact_info(
            id=id,
            auth_info=auth_info,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_info(response_xml)

    def contact_create(
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
        """
        Create a contact.

        Args:
            id: Contact ID
            name: Contact name
            email: Email address
            city: City
            country_code: 2-letter country code
            org: Organization name
            street: Street address lines
            state: State/province
            postal_code: Postal/ZIP code
            voice: Phone number
            fax: Fax number
            auth_info: Auth info (auto-generated if not provided)
            postal_type: Postal info type - int or loc (default: int)

        Returns:
            Contact create result

        Raises:
            EPPObjectExists: If contact already exists
            EPPCommandError: If command fails
        """
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
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_contact_create(response_xml)

    def contact_delete(self, id: str) -> EPPResponse:
        """
        Delete a contact.

        Args:
            id: Contact ID

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If contact not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_contact_delete(
            id=id,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def contact_update(
        self,
        id: str,
        add_status: List[str] = None,
        rem_status: List[str] = None,
        new_email: str = None,
        new_voice: str = None,
        new_fax: str = None,
        new_auth_info: str = None,
    ) -> EPPResponse:
        """
        Update a contact.

        Args:
            id: Contact ID
            add_status: Status values to add
            rem_status: Status values to remove
            new_email: New email address
            new_voice: New phone number
            new_fax: New fax number
            new_auth_info: New auth info

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If contact not found
            EPPCommandError: If command fails
        """
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
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    # =========================================================================
    # Host Commands
    # =========================================================================

    def host_check(self, names: Union[str, List[str]]) -> HostCheckResult:
        """
        Check host availability.

        Args:
            names: Host name(s) to check

        Returns:
            Host check result

        Raises:
            EPPCommandError: If command fails
        """
        if isinstance(names, str):
            names = [names]

        xml = XMLBuilder.build_host_check(
            names=names,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_check(response_xml)

    def host_info(self, name: str) -> HostInfo:
        """
        Get host information.

        Args:
            name: Host name

        Returns:
            Host info

        Raises:
            EPPObjectNotFound: If host not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_host_info(
            name=name,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_info(response_xml)

    def host_create(
        self,
        name: str,
        ipv4: List[str] = None,
        ipv6: List[str] = None,
    ) -> HostCreateResult:
        """
        Create a host.

        Args:
            name: Host name
            ipv4: List of IPv4 addresses
            ipv6: List of IPv6 addresses

        Returns:
            Host create result

        Raises:
            EPPObjectExists: If host already exists
            EPPCommandError: If command fails
        """
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
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        self._check_response(response)
        return XMLParser.parse_host_create(response_xml)

    def host_delete(self, name: str) -> EPPResponse:
        """
        Delete a host.

        Args:
            name: Host name

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If host not found
            EPPCommandError: If command fails
        """
        xml = XMLBuilder.build_host_delete(
            name=name,
            cl_trid=self._generate_cl_trid(),
        )
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)

    def host_update(
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
        """
        Update a host.

        Args:
            name: Host name
            add_ipv4: IPv4 addresses to add
            add_ipv6: IPv6 addresses to add
            rem_ipv4: IPv4 addresses to remove
            rem_ipv6: IPv6 addresses to remove
            add_status: Status values to add
            rem_status: Status values to remove
            new_name: New host name

        Returns:
            EPP response

        Raises:
            EPPObjectNotFound: If host not found
            EPPCommandError: If command fails
        """
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
        response_xml = self._send_command(xml)
        response = XMLParser.parse_response(response_xml)

        return self._check_response(response)
