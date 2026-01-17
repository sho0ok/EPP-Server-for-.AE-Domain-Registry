#!/usr/bin/env python3
"""
Mock EPP Server for Testing

A comprehensive mock EPP server that responds to ALL EPP commands.
Used for testing the EPP client without a real registry connection.
"""

import asyncio
import logging
import ssl
import struct
import re
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock_epp_server")

# Test certificates path
CERT_DIR = Path("/home/alhammadi/Downloads/ARI/test-certs")

# EPP XML Templates
GREETING_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <greeting>
    <svID>Mock EPP Test Server</svID>
    <svDate>%s</svDate>
    <svcMenu>
      <version>1.0</version>
      <lang>en</lang>
      <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
      <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
      <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
    </svcMenu>
    <dcp>
      <access><all/></access>
      <statement>
        <purpose><admin/><prov/></purpose>
        <recipient><ours/></recipient>
        <retention><stated/></retention>
      </statement>
    </dcp>
  </greeting>
</epp>"""

SUCCESS_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

PENDING_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1001">
      <msg>Command completed successfully; action pending</msg>
    </result>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

LOGOUT_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1500">
      <msg>Command completed successfully; ending session</msg>
    </result>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

AUTH_ERROR_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="2200">
      <msg>Authentication error</msg>
    </result>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

# Domain responses
DOMAIN_CHECK_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <domain:chkData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        %s
      </domain:chkData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

DOMAIN_INFO_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <domain:infData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>%s</domain:name>
        <domain:roid>DOM123-TEST</domain:roid>
        <domain:status s="ok"/>
        <domain:registrant>REG001</domain:registrant>
        <domain:contact type="admin">ADM001</domain:contact>
        <domain:contact type="tech">TCH001</domain:contact>
        <domain:ns>
          <domain:hostObj>ns1.example.test</domain:hostObj>
          <domain:hostObj>ns2.example.test</domain:hostObj>
        </domain:ns>
        <domain:clID>testregistrar</domain:clID>
        <domain:crID>testregistrar</domain:crID>
        <domain:crDate>2024-01-01T00:00:00Z</domain:crDate>
        <domain:exDate>2025-01-01T00:00:00Z</domain:exDate>
        <domain:authInfo>
          <domain:pw>auth123</domain:pw>
        </domain:authInfo>
      </domain:infData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

# Domain info response for restricted zones (includes AE eligibility extension)
DOMAIN_INFO_RESTRICTED_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <domain:infData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>%s</domain:name>
        <domain:roid>DOM123-TEST</domain:roid>
        <domain:status s="ok"/>
        <domain:registrant>REG001</domain:registrant>
        <domain:contact type="admin">ADM001</domain:contact>
        <domain:contact type="tech">TCH001</domain:contact>
        <domain:ns>
          <domain:hostObj>ns1.example.test</domain:hostObj>
          <domain:hostObj>ns2.example.test</domain:hostObj>
        </domain:ns>
        <domain:clID>testregistrar</domain:clID>
        <domain:crID>testregistrar</domain:crID>
        <domain:crDate>2024-01-01T00:00:00Z</domain:crDate>
        <domain:exDate>2025-01-01T00:00:00Z</domain:exDate>
        <domain:authInfo>
          <domain:pw>auth123</domain:pw>
        </domain:authInfo>
      </domain:infData>
    </resData>
    <extension>
      <aeEligibility:infData xmlns:aeEligibility="urn:aeda:params:xml:ns:aeEligibility-1.0">
        <aeEligibility:eligibilityType>TradeLicense</aeEligibility:eligibilityType>
        <aeEligibility:eligibilityName>Example Company LLC</aeEligibility:eligibilityName>
        <aeEligibility:eligibilityID>123456</aeEligibility:eligibilityID>
        <aeEligibility:eligibilityIDType>TradeLicense</aeEligibility:eligibilityIDType>
        <aeEligibility:policyReason>1</aeEligibility:policyReason>
      </aeEligibility:infData>
    </extension>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

DOMAIN_CREATE_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <domain:creData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>%s</domain:name>
        <domain:crDate>%s</domain:crDate>
        <domain:exDate>%s</domain:exDate>
      </domain:creData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

DOMAIN_RENEW_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <domain:renData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>%s</domain:name>
        <domain:exDate>%s</domain:exDate>
      </domain:renData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

DOMAIN_TRANSFER_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1001">
      <msg>Command completed successfully; action pending</msg>
    </result>
    <resData>
      <domain:trnData xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>%s</domain:name>
        <domain:trStatus>pending</domain:trStatus>
        <domain:reID>newregistrar</domain:reID>
        <domain:reDate>%s</domain:reDate>
        <domain:acID>testregistrar</domain:acID>
        <domain:acDate>%s</domain:acDate>
        <domain:exDate>%s</domain:exDate>
      </domain:trnData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

# Contact responses
CONTACT_CHECK_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <contact:chkData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        %s
      </contact:chkData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

CONTACT_INFO_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <contact:infData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        <contact:id>%s</contact:id>
        <contact:roid>CON123-TEST</contact:roid>
        <contact:status s="ok"/>
        <contact:postalInfo type="int">
          <contact:name>Test Contact</contact:name>
          <contact:org>Test Organization</contact:org>
          <contact:addr>
            <contact:street>123 Test Street</contact:street>
            <contact:city>Test City</contact:city>
            <contact:sp>Test State</contact:sp>
            <contact:pc>12345</contact:pc>
            <contact:cc>AE</contact:cc>
          </contact:addr>
        </contact:postalInfo>
        <contact:voice>+971.41234567</contact:voice>
        <contact:fax>+971.41234568</contact:fax>
        <contact:email>test@example.ae</contact:email>
        <contact:clID>testregistrar</contact:clID>
        <contact:crID>testregistrar</contact:crID>
        <contact:crDate>2024-01-01T00:00:00Z</contact:crDate>
        <contact:authInfo>
          <contact:pw>auth123</contact:pw>
        </contact:authInfo>
      </contact:infData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

CONTACT_CREATE_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <contact:creData xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        <contact:id>%s</contact:id>
        <contact:crDate>%s</contact:crDate>
      </contact:creData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

# Host responses
HOST_CHECK_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <host:chkData xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        %s
      </host:chkData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

HOST_INFO_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <host:infData xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>%s</host:name>
        <host:roid>HOST123-TEST</host:roid>
        <host:status s="ok"/>
        <host:addr ip="v4">192.0.2.1</host:addr>
        <host:addr ip="v6">2001:db8::1</host:addr>
        <host:clID>testregistrar</host:clID>
        <host:crID>testregistrar</host:crID>
        <host:crDate>2024-01-01T00:00:00Z</host:crDate>
      </host:infData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""

HOST_CREATE_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <response>
    <result code="1000">
      <msg>Command completed successfully</msg>
    </result>
    <resData>
      <host:creData xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>%s</host:name>
        <host:crDate>%s</host:crDate>
      </host:creData>
    </resData>
    <trID>
      <clTRID>%s</clTRID>
      <svTRID>MOCK-SRV-%s</svTRID>
    </trID>
  </response>
</epp>"""


def frame_message(data: bytes) -> bytes:
    """Add EPP framing (4-byte length prefix)."""
    length = len(data) + 4
    return struct.pack(">I", length) + data


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read an EPP frame from the stream."""
    length_bytes = await reader.readexactly(4)
    length = struct.unpack(">I", length_bytes)[0]
    payload = await reader.readexactly(length - 4)
    return payload


def extract_cltrid(xml_data: bytes) -> bytes:
    """Extract clTRID from XML command."""
    match = re.search(rb"<clTRID>([^<]+)</clTRID>", xml_data)
    if match:
        return match.group(1)
    return b"unknown"


def extract_command_type(xml_data: bytes) -> str:
    """Determine command type from XML."""
    xml_str = xml_data.decode("utf-8", errors="replace").lower()

    # Session commands
    if "<login" in xml_str:
        return "login"
    elif "<logout" in xml_str:
        return "logout"
    elif "<hello" in xml_str:
        return "hello"
    elif "<poll op=\"req\"" in xml_str or "<poll op='req'" in xml_str:
        return "poll_req"
    elif "<poll op=\"ack\"" in xml_str or "<poll op='ack'" in xml_str:
        return "poll_ack"

    # Domain commands
    elif "domain:check" in xml_str:
        return "domain_check"
    elif "domain:info" in xml_str:
        return "domain_info"
    elif "domain:create" in xml_str:
        return "domain_create"
    elif "domain:delete" in xml_str:
        return "domain_delete"
    elif "domain:renew" in xml_str:
        return "domain_renew"
    elif "domain:update" in xml_str:
        return "domain_update"
    elif "domain:transfer" in xml_str:
        if 'op="request"' in xml_str or "op='request'" in xml_str:
            return "domain_transfer_request"
        elif 'op="query"' in xml_str or "op='query'" in xml_str:
            return "domain_transfer_query"
        elif 'op="approve"' in xml_str or "op='approve'" in xml_str:
            return "domain_transfer_approve"
        elif 'op="reject"' in xml_str or "op='reject'" in xml_str:
            return "domain_transfer_reject"
        elif 'op="cancel"' in xml_str or "op='cancel'" in xml_str:
            return "domain_transfer_cancel"
        return "domain_transfer"

    # Contact commands
    elif "contact:check" in xml_str:
        return "contact_check"
    elif "contact:info" in xml_str:
        return "contact_info"
    elif "contact:create" in xml_str:
        return "contact_create"
    elif "contact:delete" in xml_str:
        return "contact_delete"
    elif "contact:update" in xml_str:
        return "contact_update"

    # Host commands
    elif "host:check" in xml_str:
        return "host_check"
    elif "host:info" in xml_str:
        return "host_info"
    elif "host:create" in xml_str:
        return "host_create"
    elif "host:delete" in xml_str:
        return "host_delete"
    elif "host:update" in xml_str:
        return "host_update"

    return "unknown"


def extract_domain_names(xml_data: bytes) -> list:
    """Extract domain names from check command."""
    matches = re.findall(rb"<domain:name>([^<]+)</domain:name>", xml_data)
    return [m.decode("utf-8") for m in matches]


def extract_domain_name(xml_data: bytes) -> str:
    """Extract single domain name."""
    match = re.search(rb"<domain:name[^>]*>([^<]+)</domain:name>", xml_data)
    return match.group(1).decode("utf-8") if match else "unknown.test"


def extract_contact_ids(xml_data: bytes) -> list:
    """Extract contact IDs from check command."""
    matches = re.findall(rb"<contact:id>([^<]+)</contact:id>", xml_data)
    return [m.decode("utf-8") for m in matches]


def extract_contact_id(xml_data: bytes) -> str:
    """Extract single contact ID."""
    match = re.search(rb"<contact:id>([^<]+)</contact:id>", xml_data)
    return match.group(1).decode("utf-8") if match else "unknown"


def extract_host_names(xml_data: bytes) -> list:
    """Extract host names from check command."""
    matches = re.findall(rb"<host:name>([^<]+)</host:name>", xml_data)
    return [m.decode("utf-8") for m in matches]


def extract_host_name(xml_data: bytes) -> str:
    """Extract single host name."""
    match = re.search(rb"<host:name>([^<]+)</host:name>", xml_data)
    return match.group(1).decode("utf-8") if match else "unknown.test"


def check_login_credentials(xml_data: bytes) -> bool:
    """Check if login credentials are valid (mock)."""
    clid_match = re.search(rb"<clID>([^<]+)</clID>", xml_data)
    pw_match = re.search(rb"<pw>([^<]+)</pw>", xml_data)

    if clid_match and pw_match:
        client_id = clid_match.group(1).decode("utf-8")
        password = pw_match.group(1).decode("utf-8")
        return len(client_id) > 0 and len(password) > 0
    return False


def get_timestamp() -> bytes:
    """Get current UTC timestamp."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ").encode()


def get_future_date(years: int = 1) -> bytes:
    """Get future date."""
    future = datetime.utcnow() + timedelta(days=365 * years)
    return future.strftime("%Y-%m-%dT%H:%M:%SZ").encode()


class MockEPPServer:
    """Comprehensive mock EPP server for testing."""

    def __init__(self, host: str = "localhost", port: int = 7700):
        self.host = host
        self.port = port
        self.server = None
        self.authenticated_sessions = set()

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for server."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=CERT_DIR / "server.crt",
            keyfile=CERT_DIR / "server.key"
        )
        context.load_verify_locations(cafile=CERT_DIR / "ca.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle a client connection."""
        peername = writer.get_extra_info("peername")
        session_id = id(writer)
        logger.info(f"Client connected: {peername}")

        try:
            # Send greeting
            greeting = GREETING_XML % get_timestamp()
            writer.write(frame_message(greeting))
            await writer.drain()
            logger.info(f"Sent greeting to {peername}")

            # Command loop
            while True:
                try:
                    xml_data = await asyncio.wait_for(read_frame(reader), timeout=60.0)
                except asyncio.TimeoutError:
                    logger.info(f"Client timeout: {peername}")
                    break
                except asyncio.IncompleteReadError:
                    logger.info(f"Client disconnected: {peername}")
                    break

                cmd_type = extract_command_type(xml_data)
                cltrid = extract_cltrid(xml_data)
                svtrid = datetime.utcnow().strftime("%Y%m%d%H%M%S").encode()

                logger.info(f"Received command: {cmd_type} from {peername}")

                response = self.process_command(cmd_type, xml_data, cltrid, svtrid, session_id)

                if cmd_type == "logout":
                    writer.write(frame_message(response))
                    await writer.drain()
                    break

                writer.write(frame_message(response))
                await writer.drain()

        except Exception as e:
            logger.error(f"Error handling client {peername}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.authenticated_sessions.discard(session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info(f"Client disconnected: {peername}")

    def process_command(self, cmd_type: str, xml_data: bytes, cltrid: bytes, svtrid: bytes, session_id: int) -> bytes:
        """Process EPP command and return response."""

        # Session commands
        if cmd_type == "hello":
            return GREETING_XML % get_timestamp()

        elif cmd_type == "login":
            if check_login_credentials(xml_data):
                self.authenticated_sessions.add(session_id)
                logger.info("Login successful")
                return SUCCESS_RESPONSE % (cltrid, svtrid)
            else:
                logger.warning("Login failed")
                return AUTH_ERROR_RESPONSE % (cltrid, svtrid)

        elif cmd_type == "logout":
            self.authenticated_sessions.discard(session_id)
            return LOGOUT_RESPONSE % (cltrid, svtrid)

        elif cmd_type == "poll_req":
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        elif cmd_type == "poll_ack":
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        # Domain commands
        elif cmd_type == "domain_check":
            domains = extract_domain_names(xml_data)
            check_results = []
            for domain in domains:
                avail = "0" if domain.startswith("taken") else "1"
                check_results.append(
                    f'<domain:cd><domain:name avail="{avail}">{domain}</domain:name></domain:cd>'
                )
            results_xml = "\n        ".join(check_results).encode()
            return DOMAIN_CHECK_RESPONSE % (results_xml, cltrid, svtrid)

        elif cmd_type == "domain_info":
            domain = extract_domain_name(xml_data)
            # Check if domain is in a restricted zone that requires eligibility
            restricted_zones = ['.co.ae', '.gov.ae', '.ac.ae', '.sch.ae', '.mil.ae', '.net.ae', '.org.ae']
            is_restricted = any(domain.lower().endswith(zone) for zone in restricted_zones)
            if is_restricted:
                return DOMAIN_INFO_RESTRICTED_RESPONSE % (domain.encode(), cltrid, svtrid)
            return DOMAIN_INFO_RESPONSE % (domain.encode(), cltrid, svtrid)

        elif cmd_type == "domain_create":
            domain = extract_domain_name(xml_data)
            cr_date = get_timestamp()
            ex_date = get_future_date(1)
            return DOMAIN_CREATE_RESPONSE % (domain.encode(), cr_date, ex_date, cltrid, svtrid)

        elif cmd_type == "domain_delete":
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        elif cmd_type == "domain_renew":
            domain = extract_domain_name(xml_data)
            ex_date = get_future_date(2)
            return DOMAIN_RENEW_RESPONSE % (domain.encode(), ex_date, cltrid, svtrid)

        elif cmd_type == "domain_update":
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        elif cmd_type in ("domain_transfer_request", "domain_transfer_query", "domain_transfer"):
            domain = extract_domain_name(xml_data)
            re_date = get_timestamp()
            ac_date = get_future_date(0)  # 5 days later typically
            ex_date = get_future_date(1)
            return DOMAIN_TRANSFER_RESPONSE % (domain.encode(), re_date, ac_date, ex_date, cltrid, svtrid)

        elif cmd_type in ("domain_transfer_approve", "domain_transfer_reject", "domain_transfer_cancel"):
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        # Contact commands
        elif cmd_type == "contact_check":
            contacts = extract_contact_ids(xml_data)
            check_results = []
            for contact in contacts:
                avail = "0" if contact.startswith("taken") else "1"
                check_results.append(
                    f'<contact:cd><contact:id avail="{avail}">{contact}</contact:id></contact:cd>'
                )
            results_xml = "\n        ".join(check_results).encode()
            return CONTACT_CHECK_RESPONSE % (results_xml, cltrid, svtrid)

        elif cmd_type == "contact_info":
            contact_id = extract_contact_id(xml_data)
            return CONTACT_INFO_RESPONSE % (contact_id.encode(), cltrid, svtrid)

        elif cmd_type == "contact_create":
            contact_id = extract_contact_id(xml_data)
            cr_date = get_timestamp()
            return CONTACT_CREATE_RESPONSE % (contact_id.encode(), cr_date, cltrid, svtrid)

        elif cmd_type == "contact_delete":
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        elif cmd_type == "contact_update":
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        # Host commands
        elif cmd_type == "host_check":
            hosts = extract_host_names(xml_data)
            check_results = []
            for host in hosts:
                avail = "0" if host.startswith("taken") else "1"
                check_results.append(
                    f'<host:cd><host:name avail="{avail}">{host}</host:name></host:cd>'
                )
            results_xml = "\n        ".join(check_results).encode()
            return HOST_CHECK_RESPONSE % (results_xml, cltrid, svtrid)

        elif cmd_type == "host_info":
            host_name = extract_host_name(xml_data)
            return HOST_INFO_RESPONSE % (host_name.encode(), cltrid, svtrid)

        elif cmd_type == "host_create":
            host_name = extract_host_name(xml_data)
            cr_date = get_timestamp()
            return HOST_CREATE_RESPONSE % (host_name.encode(), cr_date, cltrid, svtrid)

        elif cmd_type == "host_delete":
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        elif cmd_type == "host_update":
            return SUCCESS_RESPONSE % (cltrid, svtrid)

        # Unknown command - return generic success
        else:
            logger.warning(f"Unknown command type: {cmd_type}")
            return SUCCESS_RESPONSE % (cltrid, svtrid)

    async def start(self):
        """Start the mock server."""
        ssl_context = self.create_ssl_context()

        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            ssl=ssl_context
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"Mock EPP Server listening on {addrs}")

        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        """Stop the mock server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("Mock EPP Server stopped")


async def main():
    """Run the mock server."""
    server = MockEPPServer(host="localhost", port=7700)
    try:
        await server.start()
    except KeyboardInterrupt:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
