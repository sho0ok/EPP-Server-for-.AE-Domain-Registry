#!/usr/bin/env python3
"""
EPP Command Test Suite

Comprehensive test suite for all EPP commands:
- Session: login, logout
- Contact: check, info, create, update, delete
- Host: check, info, create, update, delete
- Domain: check, info, create, update, renew, delete
- Transfer: request, query, approve, reject, cancel
- Poll: request, ack

Usage:
    python epp_test_suite.py --host <server> --port <port> --user <username> --password <password>

Options:
    --transfer-domain <domain>    Domain to test transfer (requires --transfer-auth)
    --transfer-auth <authinfo>    Auth code for transfer domain
    --skip-cleanup                Don't delete test objects after tests
    --verbose                     Show full XML requests/responses
"""

import argparse
import random
import socket
import ssl
import string
import struct
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# EPP Namespaces
NS = {
    'epp': 'urn:ietf:params:xml:ns:epp-1.0',
    'domain': 'urn:ietf:params:xml:ns:domain-1.0',
    'contact': 'urn:ietf:params:xml:ns:contact-1.0',
    'host': 'urn:ietf:params:xml:ns:host-1.0',
}


@dataclass
class TestResult:
    """Result of a single test."""
    name: str
    command: str
    success: bool
    response_code: int
    message: str
    duration_ms: float
    error: Optional[str] = None


@dataclass
class TestContext:
    """Shared context for tests."""
    # Generated test IDs (random suffix for uniqueness)
    suffix: str = ""
    contact_id: str = ""
    host_name: str = ""
    domain_name: str = ""

    # Created objects to track for cleanup
    created_contacts: List[str] = field(default_factory=list)
    created_hosts: List[str] = field(default_factory=list)
    created_domains: List[str] = field(default_factory=list)

    # Transfer test config
    transfer_domain: Optional[str] = None
    transfer_auth: Optional[str] = None

    # Poll message ID for ack test
    poll_msg_id: Optional[str] = None


class EPPClient:
    """Simple EPP client for testing."""

    def __init__(self, host: str, port: int, cert_file: str, key_file: str,
                 ca_file: Optional[str] = None, verbose: bool = False):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.verbose = verbose
        self.sock = None
        self.ssl_sock = None
        self.connected = False
        self.logged_in = False
        self.cl_trid_counter = 0

    def connect(self) -> Tuple[bool, str]:
        """Connect to EPP server."""
        try:
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            # Load client certificate and key
            context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

            # Load CA for server verification (optional)
            if self.ca_file:
                context.load_verify_locations(self.ca_file)
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            # Connect
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(30)
            self.ssl_sock = context.wrap_socket(self.sock, server_hostname=self.host)
            self.ssl_sock.connect((self.host, self.port))
            self.connected = True

            # Read greeting
            greeting = self._read_frame()
            if self.verbose:
                print(f"[GREETING]\n{greeting}\n")

            return True, "Connected"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        """Disconnect from server."""
        try:
            if self.ssl_sock:
                self.ssl_sock.close()
            if self.sock:
                self.sock.close()
        except:
            pass
        self.connected = False
        self.logged_in = False

    def _read_frame(self) -> str:
        """Read EPP frame."""
        # Read 4-byte length header
        header = self.ssl_sock.recv(4)
        if len(header) < 4:
            raise Exception("Connection closed")

        length = struct.unpack(">I", header)[0] - 4

        # Read data
        data = b""
        while len(data) < length:
            chunk = self.ssl_sock.recv(min(length - len(data), 8192))
            if not chunk:
                raise Exception("Connection closed")
            data += chunk

        return data.decode('utf-8')

    def _send_frame(self, xml: str):
        """Send EPP frame."""
        data = xml.encode('utf-8')
        length = len(data) + 4
        header = struct.pack(">I", length)
        self.ssl_sock.sendall(header + data)

    def _get_cl_trid(self) -> str:
        """Generate client transaction ID."""
        self.cl_trid_counter += 1
        return f"TEST-{self.cl_trid_counter:06d}"

    def send_command(self, xml: str) -> Tuple[int, str, str, ET.Element]:
        """
        Send command and get response.

        Returns:
            (response_code, message, raw_xml, root_element)
        """
        if self.verbose:
            print(f"[REQUEST]\n{xml}\n")

        self._send_frame(xml)
        response = self._read_frame()

        if self.verbose:
            print(f"[RESPONSE]\n{response}\n")

        # Parse response
        root = ET.fromstring(response)

        # Extract result code and message
        result = root.find('.//epp:result', NS)
        if result is not None:
            code = int(result.get('code', '0'))
            msg_elem = result.find('epp:msg', NS)
            msg = msg_elem.text if msg_elem is not None else ""
        else:
            code = 0
            msg = "No result found"

        return code, msg, response, root

    # =========================================================================
    # Session Commands
    # =========================================================================

    def login(self, username: str, password: str) -> Tuple[int, str]:
        """Login to EPP server."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <login>
      <clID>{username}</clID>
      <pw>{password}</pw>
      <options>
        <version>1.0</version>
        <lang>en</lang>
      </options>
      <svcs>
        <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
      </svcs>
    </login>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        if code == 1000:
            self.logged_in = True
        return code, msg

    def logout(self) -> Tuple[int, str]:
        """Logout from EPP server."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <logout/>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        if code in (1000, 1500):
            self.logged_in = False
        return code, msg

    # =========================================================================
    # Contact Commands
    # =========================================================================

    def contact_check(self, contact_ids: List[str]) -> Tuple[int, str, Dict[str, bool]]:
        """Check contact availability."""
        cl_trid = self._get_cl_trid()
        ids_xml = "\n        ".join(f"<contact:id>{cid}</contact:id>" for cid in contact_ids)
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <check>
      <contact:check xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        {ids_xml}
      </contact:check>
    </check>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, root = self.send_command(xml)

        # Parse availability
        avail = {}
        for cd in root.findall('.//contact:cd', NS):
            id_elem = cd.find('contact:id', NS)
            if id_elem is not None:
                cid = id_elem.text
                is_avail = id_elem.get('avail', '0') == '1'
                avail[cid] = is_avail

        return code, msg, avail

    def contact_info(self, contact_id: str, auth_info: Optional[str] = None) -> Tuple[int, str, Dict]:
        """Get contact info."""
        cl_trid = self._get_cl_trid()
        auth_xml = ""
        if auth_info:
            auth_xml = f"""
        <contact:authInfo>
          <contact:pw>{auth_info}</contact:pw>
        </contact:authInfo>"""

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <info>
      <contact:info xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        <contact:id>{contact_id}</contact:id>{auth_xml}
      </contact:info>
    </info>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, root = self.send_command(xml)

        # Parse basic info
        info = {}
        inf_data = root.find('.//contact:infData', NS)
        if inf_data is not None:
            for elem in ['id', 'roid', 'email', 'clID', 'crID']:
                e = inf_data.find(f'contact:{elem}', NS)
                if e is not None:
                    info[elem] = e.text

        return code, msg, info

    def contact_create(self, contact_id: str, name: str, email: str,
                       city: str, country: str, voice: str = "+971.12345678") -> Tuple[int, str]:
        """Create a contact."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <create>
      <contact:create xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        <contact:id>{contact_id}</contact:id>
        <contact:postalInfo type="int">
          <contact:name>{name}</contact:name>
          <contact:addr>
            <contact:city>{city}</contact:city>
            <contact:cc>{country}</contact:cc>
          </contact:addr>
        </contact:postalInfo>
        <contact:voice>{voice}</contact:voice>
        <contact:email>{email}</contact:email>
        <contact:authInfo>
          <contact:pw>b#i7b#u-</contact:pw>
        </contact:authInfo>
      </contact:create>
    </create>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    def contact_update(self, contact_id: str, new_email: Optional[str] = None,
                       add_status: Optional[str] = None,
                       rem_status: Optional[str] = None) -> Tuple[int, str]:
        """Update a contact."""
        cl_trid = self._get_cl_trid()

        add_xml = ""
        if add_status:
            add_xml = f"""
      <contact:add>
        <contact:status s="{add_status}"/>
      </contact:add>"""

        rem_xml = ""
        if rem_status:
            rem_xml = f"""
      <contact:rem>
        <contact:status s="{rem_status}"/>
      </contact:rem>"""

        chg_xml = ""
        if new_email:
            chg_xml = f"""
      <contact:chg>
        <contact:email>{new_email}</contact:email>
      </contact:chg>"""

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <update>
      <contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        <contact:id>{contact_id}</contact:id>{add_xml}{rem_xml}{chg_xml}
      </contact:update>
    </update>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    def contact_delete(self, contact_id: str) -> Tuple[int, str]:
        """Delete a contact."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <delete>
      <contact:delete xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
        <contact:id>{contact_id}</contact:id>
      </contact:delete>
    </delete>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    # =========================================================================
    # Host Commands
    # =========================================================================

    def host_check(self, hostnames: List[str]) -> Tuple[int, str, Dict[str, bool]]:
        """Check host availability."""
        cl_trid = self._get_cl_trid()
        names_xml = "\n        ".join(f"<host:name>{h}</host:name>" for h in hostnames)
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <check>
      <host:check xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        {names_xml}
      </host:check>
    </check>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, root = self.send_command(xml)

        avail = {}
        for cd in root.findall('.//host:cd', NS):
            name_elem = cd.find('host:name', NS)
            if name_elem is not None:
                name = name_elem.text
                is_avail = name_elem.get('avail', '0') == '1'
                avail[name] = is_avail

        return code, msg, avail

    def host_info(self, hostname: str) -> Tuple[int, str, Dict]:
        """Get host info."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <info>
      <host:info xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{hostname}</host:name>
      </host:info>
    </info>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, root = self.send_command(xml)

        info = {}
        inf_data = root.find('.//host:infData', NS)
        if inf_data is not None:
            for elem in ['name', 'roid', 'clID', 'crID']:
                e = inf_data.find(f'host:{elem}', NS)
                if e is not None:
                    info[elem] = e.text
            # Get IPs
            info['addrs'] = []
            for addr in inf_data.findall('host:addr', NS):
                info['addrs'].append({
                    'ip': addr.get('ip', 'v4'),
                    'addr': addr.text
                })

        return code, msg, info

    def host_create(self, hostname: str, addrs: Optional[List[Dict]] = None) -> Tuple[int, str]:
        """Create a host."""
        cl_trid = self._get_cl_trid()

        addr_xml = ""
        if addrs:
            for a in addrs:
                ip_type = a.get('ip', 'v4')
                addr_xml += f'\n        <host:addr ip="{ip_type}">{a["addr"]}</host:addr>'

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <create>
      <host:create xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{hostname}</host:name>{addr_xml}
      </host:create>
    </create>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    def host_update(self, hostname: str, add_addrs: Optional[List[Dict]] = None,
                    rem_addrs: Optional[List[Dict]] = None,
                    new_name: Optional[str] = None) -> Tuple[int, str]:
        """Update a host."""
        cl_trid = self._get_cl_trid()

        add_xml = ""
        if add_addrs:
            addrs = "".join(f'<host:addr ip="{a.get("ip", "v4")}">{a["addr"]}</host:addr>' for a in add_addrs)
            add_xml = f"\n      <host:add>{addrs}</host:add>"

        rem_xml = ""
        if rem_addrs:
            addrs = "".join(f'<host:addr ip="{a.get("ip", "v4")}">{a["addr"]}</host:addr>' for a in rem_addrs)
            rem_xml = f"\n      <host:rem>{addrs}</host:rem>"

        chg_xml = ""
        if new_name:
            chg_xml = f"\n      <host:chg><host:name>{new_name}</host:name></host:chg>"

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <update>
      <host:update xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{hostname}</host:name>{add_xml}{rem_xml}{chg_xml}
      </host:update>
    </update>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    def host_delete(self, hostname: str) -> Tuple[int, str]:
        """Delete a host."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <delete>
      <host:delete xmlns:host="urn:ietf:params:xml:ns:host-1.0">
        <host:name>{hostname}</host:name>
      </host:delete>
    </delete>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    # =========================================================================
    # Domain Commands
    # =========================================================================

    def domain_check(self, domains: List[str]) -> Tuple[int, str, Dict[str, bool]]:
        """Check domain availability."""
        cl_trid = self._get_cl_trid()
        names_xml = "\n        ".join(f"<domain:name>{d}</domain:name>" for d in domains)
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <check>
      <domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        {names_xml}
      </domain:check>
    </check>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, root = self.send_command(xml)

        avail = {}
        for cd in root.findall('.//domain:cd', NS):
            name_elem = cd.find('domain:name', NS)
            if name_elem is not None:
                name = name_elem.text
                is_avail = name_elem.get('avail', '0') == '1'
                avail[name] = is_avail

        return code, msg, avail

    def domain_info(self, domain: str, auth_info: Optional[str] = None) -> Tuple[int, str, Dict]:
        """Get domain info."""
        cl_trid = self._get_cl_trid()
        auth_xml = ""
        if auth_info:
            auth_xml = f"""
        <domain:authInfo>
          <domain:pw>{auth_info}</domain:pw>
        </domain:authInfo>"""

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <info>
      <domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name hosts="all">{domain}</domain:name>{auth_xml}
      </domain:info>
    </info>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, root = self.send_command(xml)

        info = {}
        inf_data = root.find('.//domain:infData', NS)
        if inf_data is not None:
            for elem in ['name', 'roid', 'clID', 'crID', 'exDate']:
                e = inf_data.find(f'domain:{elem}', NS)
                if e is not None:
                    info[elem] = e.text
            # Get nameservers
            info['ns'] = []
            ns_elem = inf_data.find('domain:ns', NS)
            if ns_elem is not None:
                for host in ns_elem.findall('domain:hostObj', NS):
                    info['ns'].append(host.text)

        return code, msg, info

    def domain_create(self, domain: str, period: int, registrant: str,
                      admin: str, tech: str, ns: List[str],
                      auth_info: str = "b#i7b#u-") -> Tuple[int, str]:
        """Create a domain."""
        cl_trid = self._get_cl_trid()

        ns_xml = "\n        ".join(f"<domain:hostObj>{h}</domain:hostObj>" for h in ns)

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <create>
      <domain:create xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{domain}</domain:name>
        <domain:period unit="y">{period}</domain:period>
        <domain:ns>
          {ns_xml}
        </domain:ns>
        <domain:registrant>{registrant}</domain:registrant>
        <domain:contact type="admin">{admin}</domain:contact>
        <domain:contact type="tech">{tech}</domain:contact>
        <domain:authInfo>
          <domain:pw>{auth_info}</domain:pw>
        </domain:authInfo>
      </domain:create>
    </create>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    def domain_update(self, domain: str,
                      add_ns: Optional[List[str]] = None,
                      rem_ns: Optional[List[str]] = None,
                      add_status: Optional[str] = None,
                      rem_status: Optional[str] = None) -> Tuple[int, str]:
        """Update a domain."""
        cl_trid = self._get_cl_trid()

        add_xml = ""
        if add_ns or add_status:
            add_parts = []
            if add_ns:
                ns_xml = "".join(f"<domain:hostObj>{h}</domain:hostObj>" for h in add_ns)
                add_parts.append(f"<domain:ns>{ns_xml}</domain:ns>")
            if add_status:
                add_parts.append(f'<domain:status s="{add_status}"/>')
            add_xml = f"\n      <domain:add>{''.join(add_parts)}</domain:add>"

        rem_xml = ""
        if rem_ns or rem_status:
            rem_parts = []
            if rem_ns:
                ns_xml = "".join(f"<domain:hostObj>{h}</domain:hostObj>" for h in rem_ns)
                rem_parts.append(f"<domain:ns>{ns_xml}</domain:ns>")
            if rem_status:
                rem_parts.append(f'<domain:status s="{rem_status}"/>')
            rem_xml = f"\n      <domain:rem>{''.join(rem_parts)}</domain:rem>"

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <update>
      <domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{domain}</domain:name>{add_xml}{rem_xml}
      </domain:update>
    </update>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    def domain_renew(self, domain: str, cur_exp_date: str, period: int = 1) -> Tuple[int, str]:
        """Renew a domain."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <renew>
      <domain:renew xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{domain}</domain:name>
        <domain:curExpDate>{cur_exp_date}</domain:curExpDate>
        <domain:period unit="y">{period}</domain:period>
      </domain:renew>
    </renew>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    def domain_delete(self, domain: str) -> Tuple[int, str]:
        """Delete a domain."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <delete>
      <domain:delete xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{domain}</domain:name>
      </domain:delete>
    </delete>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    def domain_transfer(self, domain: str, op: str, auth_info: Optional[str] = None) -> Tuple[int, str]:
        """Transfer domain (request/query/approve/reject/cancel)."""
        cl_trid = self._get_cl_trid()

        auth_xml = ""
        if auth_info:
            auth_xml = f"""
        <domain:authInfo>
          <domain:pw>{auth_info}</domain:pw>
        </domain:authInfo>"""

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <transfer op="{op}">
      <domain:transfer xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{domain}</domain:name>{auth_xml}
      </domain:transfer>
    </transfer>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg

    # =========================================================================
    # Poll Commands
    # =========================================================================

    def poll_request(self) -> Tuple[int, str, Optional[str], Optional[str]]:
        """Request poll message."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <poll op="req"/>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, root = self.send_command(xml)

        # Extract message ID and count
        msg_id = None
        msg_count = None
        msgQ = root.find('.//epp:msgQ', NS)
        if msgQ is not None:
            msg_id = msgQ.get('id')
            msg_count = msgQ.get('count')

        return code, msg, msg_id, msg_count

    def poll_ack(self, msg_id: str) -> Tuple[int, str]:
        """Acknowledge poll message."""
        cl_trid = self._get_cl_trid()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <poll op="ack" msgID="{msg_id}"/>
    <clTRID>{cl_trid}</clTRID>
  </command>
</epp>"""
        code, msg, _, _ = self.send_command(xml)
        return code, msg


class EPPTestSuite:
    """Test suite for EPP commands."""

    def __init__(self, client: EPPClient, ctx: TestContext, skip_cleanup: bool = False):
        self.client = client
        self.ctx = ctx
        self.skip_cleanup = skip_cleanup
        self.results: List[TestResult] = []

    def run_test(self, name: str, command: str, test_func) -> TestResult:
        """Run a single test and record result."""
        start = time.time()
        try:
            code, msg = test_func()
            success = 1000 <= code < 2000
            duration = (time.time() - start) * 1000
            result = TestResult(
                name=name,
                command=command,
                success=success,
                response_code=code,
                message=msg,
                duration_ms=duration
            )
        except Exception as e:
            duration = (time.time() - start) * 1000
            result = TestResult(
                name=name,
                command=command,
                success=False,
                response_code=0,
                message="",
                duration_ms=duration,
                error=str(e)
            )

        self.results.append(result)
        status = "PASS" if result.success else "FAIL"
        print(f"  [{status}] {name}: {result.response_code} - {result.message or result.error}")
        return result

    def run_all_tests(self, username: str, password: str):
        """Run all tests."""
        print("\n" + "=" * 70)
        print("EPP COMMAND TEST SUITE")
        print("=" * 70)
        print(f"Server: {self.client.host}:{self.client.port}")
        print(f"Test ID Suffix: {self.ctx.suffix}")
        print("=" * 70)

        # Connect
        print("\n[CONNECT]")
        ok, msg = self.client.connect()
        if not ok:
            print(f"  [FAIL] Connection failed: {msg}")
            return
        print(f"  [PASS] Connected to server")

        try:
            # Session tests
            self._run_session_tests(username, password)

            if not self.client.logged_in:
                print("\n[ABORT] Login failed, cannot continue tests")
                return

            # Contact tests
            self._run_contact_tests()

            # Host tests
            self._run_host_tests()

            # Domain tests
            self._run_domain_tests()

            # Transfer tests (if configured)
            if self.ctx.transfer_domain and self.ctx.transfer_auth:
                self._run_transfer_tests()

            # Poll tests
            self._run_poll_tests()

            # Error case tests
            self._run_error_tests()

            # Cleanup
            if not self.skip_cleanup:
                self._run_cleanup()

            # Logout
            print("\n[LOGOUT]")
            self.run_test("Logout", "logout", lambda: self.client.logout())

        finally:
            self.client.disconnect()
            self._print_summary()

    def _run_session_tests(self, username: str, password: str):
        """Run session tests."""
        print("\n[SESSION TESTS]")
        self.run_test("Login", "login", lambda: self.client.login(username, password))

    def _run_contact_tests(self):
        """Run contact tests."""
        print("\n[CONTACT TESTS]")

        contact_id = self.ctx.contact_id

        # Check
        def check():
            code, msg, avail = self.client.contact_check([contact_id])
            return code, msg
        self.run_test("Contact Check", "contact:check", check)

        # Create
        def create():
            code, msg = self.client.contact_create(
                contact_id=contact_id,
                name="Test Contact",
                email="test@example.ae",
                city="Abu Dhabi",
                country="AE"
            )
            if code == 1000:
                self.ctx.created_contacts.append(contact_id)
            return code, msg
        self.run_test("Contact Create", "contact:create", create)

        # Info
        def info():
            code, msg, data = self.client.contact_info(contact_id)
            return code, msg
        self.run_test("Contact Info", "contact:info", info)

        # Update
        def update():
            return self.client.contact_update(contact_id, new_email="updated@example.ae")
        self.run_test("Contact Update", "contact:update", update)

    def _run_host_tests(self):
        """Run host tests."""
        print("\n[HOST TESTS]")

        hostname = self.ctx.host_name

        # Check
        def check():
            code, msg, avail = self.client.host_check([hostname])
            return code, msg
        self.run_test("Host Check", "host:check", check)

        # Create (external host - no IPs needed)
        def create():
            code, msg = self.client.host_create(hostname)
            if code == 1000:
                self.ctx.created_hosts.append(hostname)
            return code, msg
        self.run_test("Host Create", "host:create", create)

        # Info
        def info():
            code, msg, data = self.client.host_info(hostname)
            return code, msg
        self.run_test("Host Info", "host:info", info)

        # Update (add IP)
        def update():
            return self.client.host_update(hostname, add_addrs=[{"ip": "v4", "addr": "192.0.2.1"}])
        self.run_test("Host Update", "host:update", update)

    def _run_domain_tests(self):
        """Run domain tests."""
        print("\n[DOMAIN TESTS]")

        domain = self.ctx.domain_name
        contact = self.ctx.contact_id

        # We need external nameservers for testing
        ns1 = "ns1.example.com"
        ns2 = "ns2.example.com"

        # Check
        def check():
            code, msg, avail = self.client.domain_check([domain])
            return code, msg
        self.run_test("Domain Check", "domain:check", check)

        # Create
        def create():
            code, msg = self.client.domain_create(
                domain=domain,
                period=1,
                registrant=contact,
                admin=contact,
                tech=contact,
                ns=[ns1, ns2]
            )
            if code == 1000 or code == 1001:
                self.ctx.created_domains.append(domain)
            return code, msg
        self.run_test("Domain Create", "domain:create", create)

        # Info
        exp_date = None
        def info():
            nonlocal exp_date
            code, msg, data = self.client.domain_info(domain)
            exp_date = data.get('exDate', '')[:10]  # YYYY-MM-DD
            return code, msg
        self.run_test("Domain Info", "domain:info", info)

        # Update
        def update():
            return self.client.domain_update(domain, add_status="clientHold")
        self.run_test("Domain Update (add status)", "domain:update", update)

        # Remove status for renew
        def update_rem():
            return self.client.domain_update(domain, rem_status="clientHold")
        self.run_test("Domain Update (rem status)", "domain:update", update_rem)

        # Renew
        def renew():
            if exp_date:
                return self.client.domain_renew(domain, exp_date, 1)
            return 2400, "No expiry date available"
        self.run_test("Domain Renew", "domain:renew", renew)

    def _run_transfer_tests(self):
        """Run transfer tests."""
        print("\n[TRANSFER TESTS]")

        domain = self.ctx.transfer_domain
        auth = self.ctx.transfer_auth

        # Query (should work without auth)
        def query():
            return self.client.domain_transfer(domain, "query")
        self.run_test("Transfer Query", "domain:transfer query", query)

        # Request
        def request():
            return self.client.domain_transfer(domain, "request", auth)
        self.run_test("Transfer Request", "domain:transfer request", request)

    def _run_poll_tests(self):
        """Run poll tests."""
        print("\n[POLL TESTS]")

        # Request
        def request():
            code, msg, msg_id, count = self.client.poll_request()
            if msg_id:
                self.ctx.poll_msg_id = msg_id
            return code, msg
        self.run_test("Poll Request", "poll:request", request)

        # Ack (if we got a message)
        if self.ctx.poll_msg_id:
            def ack():
                return self.client.poll_ack(self.ctx.poll_msg_id)
            self.run_test("Poll Ack", "poll:ack", ack)

    def _run_error_tests(self):
        """Run error case tests."""
        print("\n[ERROR CASE TESTS]")

        # Create duplicate contact
        def dup_contact():
            code, msg = self.client.contact_create(
                contact_id=self.ctx.contact_id,
                name="Duplicate",
                email="dup@example.ae",
                city="Dubai",
                country="AE"
            )
            # Expect 2302 (Object exists)
            return code, f"Expected 2302, got {code}"
        result = self.run_test("Create Duplicate Contact (expect fail)", "contact:create", dup_contact)
        # Adjust success - we WANT this to fail with 2302
        if result.response_code == 2302:
            result.success = True
            result.message = "Correctly rejected duplicate"

        # Info non-existent contact
        def no_contact():
            code, msg, _ = self.client.contact_info("NONEXISTENT-999999")
            return code, f"Expected 2303, got {code}"
        result = self.run_test("Info Non-existent Contact (expect fail)", "contact:info", no_contact)
        if result.response_code == 2303:
            result.success = True
            result.message = "Correctly returned not found"

        # Delete non-existent domain
        def no_domain():
            code, msg = self.client.domain_delete("nonexistent-999999.ae")
            return code, f"Expected 2303, got {code}"
        result = self.run_test("Delete Non-existent Domain (expect fail)", "domain:delete", no_domain)
        if result.response_code == 2303:
            result.success = True
            result.message = "Correctly returned not found"

    def _run_cleanup(self):
        """Clean up test objects."""
        print("\n[CLEANUP]")

        # Test contact delete with a standalone contact (not associated with any domain)
        standalone_contact = f"DEL-{self.ctx.suffix}"
        def create_standalone():
            code, msg = self.client.contact_create(
                contact_id=standalone_contact,
                name="Delete Test Contact",
                email="delete@example.ae",
                city="Dubai",
                country="AE"
            )
            return code, msg
        self.run_test(f"Create Standalone Contact {standalone_contact}", "contact:create", create_standalone)

        def delete_standalone():
            return self.client.contact_delete(standalone_contact)
        self.run_test(f"Delete Standalone Contact {standalone_contact}", "contact:delete", delete_standalone)

        # Delete domains first (they reference contacts/hosts)
        for domain in self.ctx.created_domains:
            def delete_domain(d=domain):
                return self.client.domain_delete(d)
            self.run_test(f"Delete Domain {domain}", "domain:delete", delete_domain)

        # Delete hosts
        for host in self.ctx.created_hosts:
            def delete_host(h=host):
                return self.client.host_delete(h)
            self.run_test(f"Delete Host {host}", "host:delete", delete_host)

        # Note: Original contact cannot be deleted as it's still associated with domain in pending delete state
        # This is correct EPP behavior - contacts linked to domains (even pending delete) cannot be removed

    def _print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)

        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        failed = total - passed

        print(f"\nTotal: {total}  |  Passed: {passed}  |  Failed: {failed}")
        print(f"Success Rate: {(passed/total*100):.1f}%" if total > 0 else "No tests run")

        if failed > 0:
            print("\nFailed Tests:")
            for r in self.results:
                if not r.success:
                    err = f" ({r.error})" if r.error else ""
                    print(f"  - {r.name}: {r.response_code} {r.message}{err}")

        print("\n" + "-" * 70)
        print(f"{'Test Name':<40} {'Command':<20} {'Code':<6} {'Time':<10} {'Status'}")
        print("-" * 70)
        for r in self.results:
            status = "PASS" if r.success else "FAIL"
            print(f"{r.name:<40} {r.command:<20} {r.response_code:<6} {r.duration_ms:>6.0f}ms   {status}")
        print("=" * 70)


def generate_test_suffix() -> str:
    """Generate random suffix for test IDs."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))


def main():
    parser = argparse.ArgumentParser(description="EPP Command Test Suite")
    parser.add_argument("--host", required=True, help="EPP server hostname")
    parser.add_argument("--port", type=int, default=700, help="EPP server port")
    parser.add_argument("--user", required=True, help="EPP username")
    parser.add_argument("--password", required=True, help="EPP password")
    parser.add_argument("--cert", required=True, help="Client certificate file (PEM)")
    parser.add_argument("--key", required=True, help="Client private key file (PEM)")
    parser.add_argument("--ca", help="CA certificate file for server verification (optional)")
    parser.add_argument("--transfer-domain", help="Domain to test transfer")
    parser.add_argument("--transfer-auth", help="Auth code for transfer domain")
    parser.add_argument("--skip-cleanup", action="store_true", help="Don't delete test objects")
    parser.add_argument("--verbose", action="store_true", help="Show XML requests/responses")

    args = parser.parse_args()

    # Generate test context
    suffix = generate_test_suffix()
    ctx = TestContext(
        suffix=suffix,
        contact_id=f"TEST-{suffix}",
        host_name=f"ns1.test-{suffix.lower()}.com",  # External host
        domain_name=f"test-{suffix.lower()}.ae",
        transfer_domain=args.transfer_domain,
        transfer_auth=args.transfer_auth
    )

    # Create client and run tests
    client = EPPClient(
        host=args.host,
        port=args.port,
        cert_file=args.cert,
        key_file=args.key,
        ca_file=args.ca,
        verbose=args.verbose
    )
    suite = EPPTestSuite(client, ctx, skip_cleanup=args.skip_cleanup)
    suite.run_all_tests(args.user, args.password)


if __name__ == "__main__":
    main()
