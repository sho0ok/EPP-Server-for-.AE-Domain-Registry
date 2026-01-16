#!/usr/bin/env python3
"""
Mock EPP Server for Testing

A simple mock EPP server that responds to basic EPP commands.
Used for testing the EPP client without a real registry connection.
"""

import asyncio
import logging
import ssl
import struct
from datetime import datetime
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
      </domain:infData>
    </resData>
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


def frame_message(data: bytes) -> bytes:
    """Add EPP framing (4-byte length prefix)."""
    length = len(data) + 4
    return struct.pack(">I", length) + data


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read an EPP frame from the stream."""
    # Read 4-byte length
    length_bytes = await reader.readexactly(4)
    length = struct.unpack(">I", length_bytes)[0]

    # Read payload (length includes the 4-byte header)
    payload = await reader.readexactly(length - 4)
    return payload


def extract_cltrid(xml_data: bytes) -> bytes:
    """Extract clTRID from XML command."""
    import re
    match = re.search(rb"<clTRID>([^<]+)</clTRID>", xml_data)
    if match:
        return match.group(1)
    return b"unknown"


def extract_command_type(xml_data: bytes) -> str:
    """Determine command type from XML."""
    xml_str = xml_data.decode("utf-8", errors="replace").lower()

    if "<login" in xml_str:
        return "login"
    elif "<logout" in xml_str:
        return "logout"
    elif "<hello" in xml_str:
        return "hello"
    elif "domain:check" in xml_str:
        return "domain_check"
    elif "domain:info" in xml_str:
        return "domain_info"
    elif "contact:check" in xml_str:
        return "contact_check"
    elif "host:check" in xml_str:
        return "host_check"
    else:
        return "unknown"


def extract_domain_names(xml_data: bytes) -> list:
    """Extract domain names from check command."""
    import re
    matches = re.findall(rb"<domain:name>([^<]+)</domain:name>", xml_data)
    return [m.decode("utf-8") for m in matches]


def extract_contact_ids(xml_data: bytes) -> list:
    """Extract contact IDs from check command."""
    import re
    matches = re.findall(rb"<contact:id>([^<]+)</contact:id>", xml_data)
    return [m.decode("utf-8") for m in matches]


def extract_host_names(xml_data: bytes) -> list:
    """Extract host names from check command."""
    import re
    matches = re.findall(rb"<host:name>([^<]+)</host:name>", xml_data)
    return [m.decode("utf-8") for m in matches]


def check_login_credentials(xml_data: bytes) -> bool:
    """Check if login credentials are valid (mock)."""
    import re
    clid_match = re.search(rb"<clID>([^<]+)</clID>", xml_data)
    pw_match = re.search(rb"<pw>([^<]+)</pw>", xml_data)

    if clid_match and pw_match:
        client_id = clid_match.group(1).decode("utf-8")
        password = pw_match.group(1).decode("utf-8")
        # Accept any non-empty credentials for testing
        return len(client_id) > 0 and len(password) > 0
    return False


class MockEPPServer:
    """Mock EPP server for testing."""

    def __init__(self, host: str = "localhost", port: int = 7700):
        self.host = host
        self.port = port
        self.server = None
        self.authenticated_sessions = set()

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for server."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load server certificate and key
        context.load_cert_chain(
            certfile=CERT_DIR / "server.crt",
            keyfile=CERT_DIR / "server.key"
        )

        # Load CA for client verification
        context.load_verify_locations(cafile=CERT_DIR / "ca.crt")

        # Require client certificate
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
            greeting = GREETING_XML % datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ").encode()
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

                # Process command
                if cmd_type == "hello":
                    greeting = GREETING_XML % datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ").encode()
                    response = greeting

                elif cmd_type == "login":
                    if check_login_credentials(xml_data):
                        self.authenticated_sessions.add(session_id)
                        response = SUCCESS_RESPONSE % (cltrid, svtrid)
                        logger.info(f"Login successful for {peername}")
                    else:
                        response = AUTH_ERROR_RESPONSE % (cltrid, svtrid)
                        logger.warning(f"Login failed for {peername}")

                elif cmd_type == "logout":
                    self.authenticated_sessions.discard(session_id)
                    response = LOGOUT_RESPONSE % (cltrid, svtrid)
                    writer.write(frame_message(response))
                    await writer.drain()
                    logger.info(f"Logout: {peername}")
                    break

                elif cmd_type == "domain_check":
                    domains = extract_domain_names(xml_data)
                    check_results = []
                    for domain in domains:
                        # Simulate: domains starting with "taken" are not available
                        avail = "0" if domain.startswith("taken") else "1"
                        check_results.append(
                            f'<domain:cd><domain:name avail="{avail}">{domain}</domain:name></domain:cd>'
                        )
                    results_xml = "\n        ".join(check_results).encode()
                    response = DOMAIN_CHECK_RESPONSE % (results_xml, cltrid, svtrid)

                elif cmd_type == "domain_info":
                    import re
                    match = re.search(rb"<domain:name[^>]*>([^<]+)</domain:name>", xml_data)
                    domain = match.group(1) if match else b"unknown.test"
                    response = DOMAIN_INFO_RESPONSE % (domain, cltrid, svtrid)

                elif cmd_type == "contact_check":
                    contacts = extract_contact_ids(xml_data)
                    check_results = []
                    for contact in contacts:
                        avail = "0" if contact.startswith("taken") else "1"
                        check_results.append(
                            f'<contact:cd><contact:id avail="{avail}">{contact}</contact:id></contact:cd>'
                        )
                    results_xml = "\n        ".join(check_results).encode()
                    response = CONTACT_CHECK_RESPONSE % (results_xml, cltrid, svtrid)

                elif cmd_type == "host_check":
                    hosts = extract_host_names(xml_data)
                    check_results = []
                    for host in hosts:
                        avail = "0" if host.startswith("taken") else "1"
                        check_results.append(
                            f'<host:cd><host:name avail="{avail}">{host}</host:name></host:cd>'
                        )
                    results_xml = "\n        ".join(check_results).encode()
                    response = HOST_CHECK_RESPONSE % (results_xml, cltrid, svtrid)

                else:
                    # Generic success for other commands
                    response = SUCCESS_RESPONSE % (cltrid, svtrid)

                writer.write(frame_message(response))
                await writer.drain()

        except Exception as e:
            logger.error(f"Error handling client {peername}: {e}")
        finally:
            self.authenticated_sessions.discard(session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info(f"Client disconnected: {peername}")

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
