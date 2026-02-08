"""
PL/SQL Stored Procedure Caller

Calls ARI's PL/SQL stored procedures directly from Python.
This replicates exactly what the old C++ EPP server did - it called
epp_domain.domain_create(), epp_domain.domain_check(), etc. which
internally handle all the complex logic (ROID generation, registry objects,
statuses, billing, audit logging, etc.).

The PL/SQL package bodies are wrapped/encrypted (.plb files), so we can't
see the implementation. But by calling the same procedures, we get identical
behavior to the old server.

Uses anonymous PL/SQL blocks to construct Oracle Object Types and call
the procedures, since python-oracledb has limitations with complex
nested Oracle types via callproc().
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from decimal import Decimal

from src.database.connection import get_pool, DatabasePool

logger = logging.getLogger("epp.database.plsql")


class EPPProcedureCaller:
    """
    Calls ARI's EPP stored procedures.

    These are the same procedures the old C++ EPP server called.
    By using them directly, we get identical portal behavior.
    """

    def __init__(self, pool: DatabasePool):
        self.pool = pool

    # ========================================================================
    # EPP Server Registration (epp package)
    # ========================================================================

    async def register_server(
        self,
        server_name: str,
        server_ip: str,
        server_port: int,
        supported_uris: List[str]
    ) -> None:
        """
        Register this EPP server in EPP_SERVERS table.

        The old C++ EPP server called epp.register_server() on startup.
        Since the wrapped PL/SQL body has an issue with EPP_STATUS,
        we first try the stored procedure, then fall back to direct INSERT.

        Args:
            server_name: Server hostname
            server_ip: Server IP address
            server_port: Server port
            supported_uris: List of supported EPP URIs
        """
        uris_csv = ", ".join(supported_uris) if supported_uris else ""

        # First, deactivate any previous entries for this server
        # (same IP may have been registered before)
        deactivate_sql = """
            UPDATE EPP_SERVERS SET EPP_STATUS = 'D'
            WHERE EPP_SERVER_IP = :server_ip
              AND EPP_SERVER_PORT = :server_port
              AND EPP_STATUS = 'A'
        """

        # Insert new active entry
        insert_sql = """
            INSERT INTO EPP_SERVERS (
                EPP_ID, EPP_DATE, EPP_STATUS,
                EPP_SERVER_NAME, EPP_SERVER_IP, EPP_SERVER_PORT, EPP_URIS
            ) VALUES (
                EPP_ID_SEQ.NEXTVAL, SYSDATE, 'A',
                :server_name, :server_ip, :server_port, :uris
            )
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()

            # Deactivate old entries
            cursor.execute(deactivate_sql, {
                "server_ip": server_ip,
                "server_port": server_port
            })

            # Register new active entry
            cursor.execute(insert_sql, {
                "server_name": server_name,
                "server_ip": server_ip,
                "server_port": server_port,
                "uris": uris_csv
            })

            conn.commit()
            cursor.close()

            logger.info(
                f"EPP server registered: name={server_name}, "
                f"ip={server_ip}, port={server_port}"
            )

    # ========================================================================
    # EPP Connection & Session (epp package)
    # ========================================================================

    @staticmethod
    def _to_ipv6_mapped(ip: str) -> str:
        """
        Convert IPv4 address to IPv6-mapped format if needed.
        ARI stores client IPs as ::ffff:x.x.x.x in ACCOUNT_EPP_ADDRESSES.
        """
        if ip and ':' not in ip:
            return f"::ffff:{ip}"
        return ip

    async def start_connection(
        self,
        username: str,
        server_name: str,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int
    ) -> Tuple[int, int]:
        """
        Call epp.start_connection() to register a new connection.

        Args:
            username: EPP username (clID)
            server_name: Server hostname
            server_ip: Server IP
            server_port: Server port
            client_ip: Client IP
            client_port: Client port

        Returns:
            Tuple of (return_code, connection_id)
        """
        # ARI stores client IPs in IPv6-mapped format (::ffff:x.x.x.x)
        client_ip_mapped = self._to_ipv6_mapped(client_ip)

        sql = """
            DECLARE
                l_rc INTEGER;
            BEGIN
                l_rc := epp.start_connection(
                    username      => :username,
                    server_name   => :server_name,
                    server_ip     => :server_ip,
                    server_port   => :server_port,
                    client_ip     => :client_ip,
                    client_port   => :client_port,
                    connection_id => :connection_id
                );
                :return_code := l_rc;
            END;
        """
        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            connection_id_var = cursor.var(int)
            return_code_var = cursor.var(int)

            cursor.execute(sql, {
                "username": username,
                "server_name": server_name,
                "server_ip": server_ip,
                "server_port": server_port,
                "client_ip": client_ip_mapped,
                "client_port": client_port,
                "connection_id": connection_id_var,
                "return_code": return_code_var
            })
            conn.commit()
            cursor.close()

            rc = self._extract_var(return_code_var, -1)
            cid = self._extract_var(connection_id_var, None)

            logger.info(f"epp.start_connection() returned rc={rc}, connection_id={cid}")
            return rc, cid

    async def end_connection(
        self,
        connection_id: int,
        reason: str = "Normal disconnect"
    ) -> int:
        """
        Call epp.end_connection() to close a connection.

        Returns:
            Return code
        """
        sql = """
            DECLARE
                l_rc INTEGER;
            BEGIN
                l_rc := epp.end_connection(
                    connection_id => :connection_id,
                    reason        => :reason
                );
                :return_code := l_rc;
            END;
        """
        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            return_code_var = cursor.var(int)

            cursor.execute(sql, {
                "connection_id": connection_id,
                "reason": reason[:100] if reason else "Normal disconnect",
                "return_code": return_code_var
            })
            conn.commit()
            cursor.close()

            rc = self._extract_var(return_code_var, -1)
            logger.info(f"epp.end_connection({connection_id}) returned rc={rc}")
            return rc

    async def login(
        self,
        connection_id: int,
        clid: str,
        pw: str,
        newpw: Optional[str],
        version: str,
        lang: str,
        obj_uris: List[str],
        ext_uris: List[str],
        cltrid: Optional[str]
    ) -> Dict[str, Any]:
        """
        Call epp.login() to authenticate a user.

        Args:
            connection_id: Connection ID from start_connection
            clid: EPP client ID (username)
            pw: Password
            newpw: New password (for password change)
            version: EPP version
            lang: Language
            obj_uris: Object URIs
            ext_uris: Extension URIs
            cltrid: Client transaction ID

        Returns:
            Dict with session_id, response_code, response_message
        """
        # Build the URN lists as Oracle collection types
        obj_uri_str = self._build_urn_list_literal(obj_uris)
        ext_uri_str = self._build_urn_list_literal(ext_uris)

        sql = f"""
            DECLARE
                l_session_id INTEGER;
                l_response   epp_response_t;
                l_objuri     urn_list_t := {obj_uri_str};
                l_exturi     urn_list_t := {ext_uri_str};
                l_code       NUMBER;
                l_msg        VARCHAR2(4000);
                l_svtrid     VARCHAR2(64);
            BEGIN
                epp.login(
                    connection_id => :connection_id,
                    clid          => :clid,
                    pw            => :pw,
                    newpw         => :newpw,
                    version       => :version,
                    lang          => :lang,
                    objuri        => l_objuri,
                    exturi        => l_exturi,
                    cltrid        => :cltrid,
                    session_id    => l_session_id,
                    response      => l_response
                );
                :session_id := l_session_id;

                -- Extract response code from first result
                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                ELSE
                    l_code := 2400;
                    l_msg := 'No response from login';
                END IF;

                -- Get svTRID
                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            session_id_var = cursor.var(int)
            response_code_var = cursor.var(int)
            response_msg_var = cursor.var(str, 4000)
            sv_trid_var = cursor.var(str, 64)

            cursor.execute(sql, {
                "connection_id": connection_id,
                "clid": clid,
                "pw": pw,
                "newpw": newpw,
                "version": version,
                "lang": lang,
                "cltrid": cltrid,
                "session_id": session_id_var,
                "response_code": response_code_var,
                "response_msg": response_msg_var,
                "sv_trid": sv_trid_var
            })
            conn.commit()
            cursor.close()

            session_id = session_id_var.getvalue()
            if isinstance(session_id, list):
                session_id = session_id[0] if session_id else None

            response_code = response_code_var.getvalue()
            if isinstance(response_code, list):
                response_code = response_code[0] if response_code else 2400

            response_msg = response_msg_var.getvalue()
            if isinstance(response_msg, list):
                response_msg = response_msg[0] if response_msg else ""

            sv_trid = sv_trid_var.getvalue()
            if isinstance(sv_trid, list):
                sv_trid = sv_trid[0] if sv_trid else None

            logger.info(
                f"epp.login() returned code={response_code}, "
                f"session_id={session_id}, msg={response_msg}"
            )

            return {
                "session_id": session_id,
                "response_code": response_code,
                "response_message": response_msg or "",
                "sv_trid": sv_trid
            }

    async def logout(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str]
    ) -> Dict[str, Any]:
        """
        Call epp.logout() to end a session.

        Returns:
            Dict with response_code, response_message, sv_trid
        """
        sql = """
            DECLARE
                l_response epp_response_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp.logout(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                ELSE
                    l_code := 1500;
                    l_msg := 'Logout successful';
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            response_code_var = cursor.var(int)
            response_msg_var = cursor.var(str, 4000)
            sv_trid_var = cursor.var(str, 64)

            cursor.execute(sql, {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "response_code": response_code_var,
                "response_msg": response_msg_var,
                "sv_trid": sv_trid_var
            })
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(response_code_var, 1500),
                "response_message": self._extract_var(response_msg_var, ""),
                "sv_trid": self._extract_var(sv_trid_var, None)
            }

    # ========================================================================
    # Domain Operations (epp_domain package)
    # ========================================================================

    async def domain_check(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        domain_names: List[str]
    ) -> Dict[str, Any]:
        """
        Call epp_domain.domain_check() to check domain availability.

        Returns:
            Dict with results list and response info
        """
        # Build the domain list literal (epp_dom_check_list_t, not epp_hos_list_t)
        domains_literal = self._build_typed_string_list("epp_dom_check_list_t", domain_names)

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_chkdata  epp_dom_chkdata_t;
                l_domains  epp_dom_check_list_t := {domains_literal};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_domain.domain_check(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    domains       => l_domains,
                    response      => l_response,
                    chkdata       => l_chkdata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
                :result_count := CASE WHEN l_chkdata IS NOT NULL THEN l_chkdata.COUNT ELSE 0 END;

                -- Store results in temp table for retrieval
                IF l_chkdata IS NOT NULL THEN
                    DELETE FROM GLOBAL_TEMP_DOMAIN_CHECK;
                    FOR i IN 1..l_chkdata.COUNT LOOP
                        INSERT INTO GLOBAL_TEMP_DOMAIN_CHECK (
                            IDX, NAME, AVAIL, REASON
                        ) VALUES (
                            i,
                            l_chkdata(i).name,
                            l_chkdata(i).avail,
                            l_chkdata(i).reason
                        );
                    END LOOP;
                END IF;
            END;
        """

        # The temp table approach may not exist, so let's use a simpler approach
        # with cursor output parameters for each result
        # Actually, let's use a different approach - parse results inline

        # Simpler approach: use DBMS_OUTPUT or just return results one-by-one
        # For domain check, since we typically check 1-5 domains, we can use
        # indexed OUT variables
        max_results = min(len(domain_names), 20)

        # Build result extraction PL/SQL
        result_vars = []
        for i in range(max_results):
            result_vars.append(f"""
                IF l_chkdata IS NOT NULL AND l_chkdata.COUNT >= {i + 1} THEN
                    :name_{i} := l_chkdata({i + 1}).name;
                    :avail_{i} := l_chkdata({i + 1}).avail;
                    :reason_{i} := l_chkdata({i + 1}).reason;
                END IF;
            """)

        result_extraction = "\n".join(result_vars)

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_chkdata  epp_dom_chkdata_t;
                l_domains  epp_dom_check_list_t := {domains_literal};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_domain.domain_check(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    domains       => l_domains,
                    response      => l_response,
                    chkdata       => l_chkdata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
                :result_count := CASE WHEN l_chkdata IS NOT NULL THEN l_chkdata.COUNT ELSE 0 END;

                {result_extraction}
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()

            # Create bind variables
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "result_count": cursor.var(int)
            }

            for i in range(max_results):
                binds[f"name_{i}"] = cursor.var(str, 255)
                binds[f"avail_{i}"] = cursor.var(str, 1)
                binds[f"reason_{i}"] = cursor.var(str, 32)

            cursor.execute(sql, binds)
            conn.commit()

            # Extract results
            response_code = self._extract_var(binds["response_code"], 2400)
            result_count = self._extract_var(binds["result_count"], 0)

            results = []
            for i in range(min(result_count, max_results)):
                name = self._extract_var(binds[f"name_{i}"], "")
                avail = self._extract_var(binds[f"avail_{i}"], "0")
                reason = self._extract_var(binds[f"reason_{i}"], None)
                results.append({
                    "name": name,
                    "avail": avail == "1",
                    "reason": reason
                })

            cursor.close()

            return {
                "response_code": response_code,
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "results": results
            }

    async def domain_create(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        period: int,
        period_unit: str,
        nameservers: Optional[List[str]],
        registrant: str,
        contacts: Optional[List[Dict[str, str]]],
        auth_info: str,
        userform: Optional[str] = None,
        idna_language: Optional[str] = None,
        extensions: Optional[List[Dict[str, Any]]] = None,
        dnssec: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Call epp_domain.domain_create() to register a new domain.

        This is the exact same procedure the old C++ EPP server called.
        It handles internally:
        - ROID generation
        - Registry object creation
        - Domain record creation
        - Registration record
        - Contact associations
        - Nameserver associations
        - Status management
        - Billing/rate calculation
        - Audit logging
        - Transaction logging

        Returns:
            Dict with:
                - response_code: EPP response code
                - response_message: Response message
                - sv_trid: Server transaction ID
                - cr_name: Created domain name
                - cr_date: Creation date
                - ex_date: Expiry date
        """
        # Build Oracle collection literals
        ns_literal = self._build_string_list_literal(nameservers) if nameservers else "epp_hos_list_t()"
        contacts_literal = self._build_contact_list_literal(contacts) if contacts else "epp_dom_contact_list_t()"
        extensions_literal = self._build_extension_list_literal(extensions) if extensions else "extension_list_t()"
        dnssec_literal = self._build_dnssec_literal(dnssec) if dnssec else "NULL"
        authinfo_literal = f"epp_authinfo_t('{self._escape_sql(auth_info)}', NULL)"

        sql = f"""
            DECLARE
                l_response     epp_response_t;
                l_cre_response epp_dom_cre_response_t;
                l_ns           epp_hos_list_t := {ns_literal};
                l_contacts     epp_dom_contact_list_t := {contacts_literal};
                l_authinfo     epp_authinfo_t := {authinfo_literal};
                l_extensions   extension_list_t := {extensions_literal};
                l_dnssec       dnssec_request_t := {dnssec_literal};
                l_code         NUMBER;
                l_msg          VARCHAR2(4000);
                l_svtrid       VARCHAR2(64);
            BEGIN
                epp_domain.domain_create(
                    p_connection_id => :connection_id,
                    p_session_id    => :session_id,
                    p_cltrid        => :cltrid,
                    p_name          => :name,
                    p_period        => :period,
                    p_period_unit   => :period_unit,
                    p_ns            => l_ns,
                    p_registrant    => :registrant,
                    p_contact       => l_contacts,
                    p_authinfo      => l_authinfo,
                    p_userform      => :userform,
                    p_idna_language => :idna_language,
                    p_extensions    => l_extensions,
                    p_dnssec        => l_dnssec,
                    p_response      => l_response,
                    p_cre_response  => l_cre_response
                );

                -- Extract response
                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                ELSE
                    l_code := 2400;
                    l_msg := 'No response from domain_create';
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;

                -- Extract create response data
                IF l_cre_response IS NOT NULL THEN
                    :cr_name := l_cre_response.crname;
                    :cr_date := TO_CHAR(l_cre_response.crdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :ex_date := TO_CHAR(l_cre_response.exdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                END IF;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()

            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "period": period,
                "period_unit": period_unit,
                "registrant": registrant,
                "userform": userform or name,
                "idna_language": idna_language,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "cr_name": cursor.var(str, 255),
                "cr_date": cursor.var(str, 30),
                "ex_date": cursor.var(str, 30)
            }

            try:
                cursor.execute(sql, binds)
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"epp_domain.domain_create() failed: {e}")
                raise

            response_code = self._extract_var(binds["response_code"], 2400)
            result = {
                "response_code": response_code,
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "cr_name": self._extract_var(binds["cr_name"], name),
                "cr_date": self._extract_var(binds["cr_date"], None),
                "ex_date": self._extract_var(binds["ex_date"], None),
            }

            cursor.close()

            logger.info(
                f"epp_domain.domain_create({name}) returned code={response_code}, "
                f"cr_date={result['cr_date']}, ex_date={result['ex_date']}"
            )

            return result

    async def domain_info(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        hosts: str = "all",
        auth_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Call epp_domain.domain_info() to get domain information.

        Uses indexed bind variable pattern to extract all collection fields
        (statuses, contacts, nameservers, hosts, extensions, DNSSEC, IDN).

        Returns:
            Dict with full domain info including all collections
        """
        authinfo_literal = (
            f"epp_authinfo_t('{self._escape_sql(auth_info)}', NULL)"
            if auth_info else "NULL"
        )

        date_fmt = 'YYYY-MM-DD"T"HH24:MI:SS".0Z"'

        # Max items for each collection
        max_statuses = 20
        max_contacts = 10
        max_ns = 13
        max_hosts = 20
        max_extensions = 5
        max_kv_per_ext = 20
        max_ds_data = 10
        max_key_data = 10

        # Build dynamic PL/SQL extraction for statuses
        status_extraction = []
        for i in range(max_statuses):
            status_extraction.append(f"""
                IF l_infdata.status IS NOT NULL AND l_infdata.status.COUNT >= {i + 1} THEN
                    :st_s_{i} := l_infdata.status({i + 1}).value;
                END IF;
            """)

        # Contacts
        contact_extraction = []
        for i in range(max_contacts):
            contact_extraction.append(f"""
                IF l_infdata.contact IS NOT NULL AND l_infdata.contact.COUNT >= {i + 1} THEN
                    :ct_id_{i} := l_infdata.contact({i + 1}).id;
                    :ct_type_{i} := l_infdata.contact({i + 1}).contact_type;
                END IF;
            """)

        # Nameservers (epp_hos_list_t = TABLE OF varchar2)
        ns_extraction = []
        for i in range(max_ns):
            ns_extraction.append(f"""
                IF l_infdata.ns IS NOT NULL AND l_infdata.ns.COUNT >= {i + 1} THEN
                    :ns_{i} := l_infdata.ns({i + 1});
                END IF;
            """)

        # Subordinate hosts
        host_extraction = []
        for i in range(max_hosts):
            host_extraction.append(f"""
                IF l_infdata.host IS NOT NULL AND l_infdata.host.COUNT >= {i + 1} THEN
                    :host_{i} := l_infdata.host({i + 1});
                END IF;
            """)

        # Extensions (extension_list_t → extension_t objects with nested KV pairs)
        ext_extraction = []
        for i in range(max_extensions):
            ext_extraction.append(f"""
                IF l_infdata.extensions IS NOT NULL AND l_infdata.extensions.COUNT >= {i + 1} THEN
                    :ext_name_{i} := l_infdata.extensions({i + 1}).extension;
                    :ext_reason_{i} := l_infdata.extensions({i + 1}).reason;
                    :ext_cv_count_{i} := CASE WHEN l_infdata.extensions({i + 1}).current_values IS NOT NULL
                        THEN l_infdata.extensions({i + 1}).current_values.COUNT ELSE 0 END;
                    -- Serialize current_values as pipe-delimited key~value pairs
                    IF l_infdata.extensions({i + 1}).current_values IS NOT NULL THEN
                        FOR j IN 1..l_infdata.extensions({i + 1}).current_values.COUNT LOOP
                            :ext_cv_{i} := :ext_cv_{i} || l_infdata.extensions({i + 1}).current_values(j).key
                                || '~' || l_infdata.extensions({i + 1}).current_values(j).value || '|';
                        END LOOP;
                    END IF;
                END IF;
            """)

        # DNSSEC DS data
        ds_extraction = []
        for i in range(max_ds_data):
            ds_extraction.append(f"""
                IF l_infdata.dnssec_data IS NOT NULL AND l_infdata.dnssec_data.ds_data IS NOT NULL
                   AND l_infdata.dnssec_data.ds_data.COUNT >= {i + 1} THEN
                    :ds_keytag_{i} := l_infdata.dnssec_data.ds_data({i + 1}).keytag;
                    :ds_alg_{i} := l_infdata.dnssec_data.ds_data({i + 1}).algorithm;
                    :ds_digtype_{i} := l_infdata.dnssec_data.ds_data({i + 1}).digest_type;
                    :ds_digest_{i} := l_infdata.dnssec_data.ds_data({i + 1}).digest;
                    IF l_infdata.dnssec_data.ds_data({i + 1}).keydata IS NOT NULL THEN
                        :ds_kd_flags_{i} := l_infdata.dnssec_data.ds_data({i + 1}).keydata.flags;
                        :ds_kd_proto_{i} := l_infdata.dnssec_data.ds_data({i + 1}).keydata.protocol;
                        :ds_kd_alg_{i} := l_infdata.dnssec_data.ds_data({i + 1}).keydata.algorithm;
                        :ds_kd_pubkey_{i} := l_infdata.dnssec_data.ds_data({i + 1}).keydata.public_key;
                    END IF;
                END IF;
            """)

        # DNSSEC standalone key data
        key_extraction = []
        for i in range(max_key_data):
            key_extraction.append(f"""
                IF l_infdata.dnssec_data IS NOT NULL AND l_infdata.dnssec_data.key_data IS NOT NULL
                   AND l_infdata.dnssec_data.key_data.COUNT >= {i + 1} THEN
                    :kd_flags_{i} := l_infdata.dnssec_data.key_data({i + 1}).flags;
                    :kd_proto_{i} := l_infdata.dnssec_data.key_data({i + 1}).protocol;
                    :kd_alg_{i} := l_infdata.dnssec_data.key_data({i + 1}).algorithm;
                    :kd_pubkey_{i} := l_infdata.dnssec_data.key_data({i + 1}).public_key;
                END IF;
            """)

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_infdata  epp_dom_infdata_t;
                l_authinfo epp_authinfo_t := {authinfo_literal};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_domain.domain_info(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    hosts         => :hosts,
                    authinfo      => l_authinfo,
                    response      => l_response,
                    infdata       => l_infdata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;

                -- Extract info data
                IF l_infdata IS NOT NULL THEN
                    :inf_name := l_infdata.name;
                    :inf_roid := l_infdata.roid;
                    :inf_registrant := l_infdata.registrant;
                    :inf_clid := l_infdata.clid;
                    :inf_crid := l_infdata.crid;
                    :inf_crdate := TO_CHAR(l_infdata.crdate, '{date_fmt}');
                    :inf_upid := l_infdata.upid;
                    :inf_update := TO_CHAR(l_infdata.up_date, '{date_fmt}');
                    :inf_exdate := TO_CHAR(l_infdata.exdate, '{date_fmt}');
                    :inf_trdate := TO_CHAR(l_infdata.trdate, '{date_fmt}');

                    IF l_infdata.authinfo IS NOT NULL THEN
                        :inf_authinfo := l_infdata.authinfo.pw;
                    END IF;

                    -- Collection counts
                    :inf_status_count := CASE WHEN l_infdata.status IS NOT NULL THEN l_infdata.status.COUNT ELSE 0 END;
                    :inf_contact_count := CASE WHEN l_infdata.contact IS NOT NULL THEN l_infdata.contact.COUNT ELSE 0 END;
                    :inf_ns_count := CASE WHEN l_infdata.ns IS NOT NULL THEN l_infdata.ns.COUNT ELSE 0 END;
                    :inf_host_count := CASE WHEN l_infdata.host IS NOT NULL THEN l_infdata.host.COUNT ELSE 0 END;
                    :inf_ext_count := CASE WHEN l_infdata.extensions IS NOT NULL THEN l_infdata.extensions.COUNT ELSE 0 END;
                    :inf_ds_count := CASE WHEN l_infdata.dnssec_data IS NOT NULL AND l_infdata.dnssec_data.ds_data IS NOT NULL
                        THEN l_infdata.dnssec_data.ds_data.COUNT ELSE 0 END;
                    :inf_kd_count := CASE WHEN l_infdata.dnssec_data IS NOT NULL AND l_infdata.dnssec_data.key_data IS NOT NULL
                        THEN l_infdata.dnssec_data.key_data.COUNT ELSE 0 END;

                    -- IDN data (single object, not collection)
                    IF l_infdata.idn_data IS NOT NULL THEN
                        :inf_idn_userform := l_infdata.idn_data.userform;
                        :inf_idn_canonical := l_infdata.idn_data.canonicalform;
                        :inf_idn_lang := l_infdata.idn_data.lang;
                    END IF;

                    -- Extract collections
                    {"".join(status_extraction)}
                    {"".join(contact_extraction)}
                    {"".join(ns_extraction)}
                    {"".join(host_extraction)}
                    {"".join(ext_extraction)}
                    {"".join(ds_extraction)}
                    {"".join(key_extraction)}
                END IF;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()

            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "hosts": hosts,
                # Response
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                # Scalar fields
                "inf_name": cursor.var(str, 255),
                "inf_roid": cursor.var(str, 89),
                "inf_registrant": cursor.var(str, 16),
                "inf_clid": cursor.var(str, 16),
                "inf_crid": cursor.var(str, 16),
                "inf_crdate": cursor.var(str, 30),
                "inf_upid": cursor.var(str, 16),
                "inf_update": cursor.var(str, 30),
                "inf_exdate": cursor.var(str, 30),
                "inf_trdate": cursor.var(str, 30),
                "inf_authinfo": cursor.var(str, 255),
                # Collection counts
                "inf_status_count": cursor.var(int),
                "inf_contact_count": cursor.var(int),
                "inf_ns_count": cursor.var(int),
                "inf_host_count": cursor.var(int),
                "inf_ext_count": cursor.var(int),
                "inf_ds_count": cursor.var(int),
                "inf_kd_count": cursor.var(int),
                # IDN data
                "inf_idn_userform": cursor.var(str, 255),
                "inf_idn_canonical": cursor.var(str, 255),
                "inf_idn_lang": cursor.var(str, 50),
            }

            # Indexed binds for collections
            for i in range(max_statuses):
                binds[f"st_s_{i}"] = cursor.var(str, 24)
            for i in range(max_contacts):
                binds[f"ct_id_{i}"] = cursor.var(str, 16)
                binds[f"ct_type_{i}"] = cursor.var(str, 10)
            for i in range(max_ns):
                binds[f"ns_{i}"] = cursor.var(str, 255)
            for i in range(max_hosts):
                binds[f"host_{i}"] = cursor.var(str, 255)
            for i in range(max_extensions):
                binds[f"ext_name_{i}"] = cursor.var(str, 100)
                binds[f"ext_reason_{i}"] = cursor.var(str, 1000)
                binds[f"ext_cv_count_{i}"] = cursor.var(int)
                binds[f"ext_cv_{i}"] = cursor.var(str, 4000)
            for i in range(max_ds_data):
                binds[f"ds_keytag_{i}"] = cursor.var(int)
                binds[f"ds_alg_{i}"] = cursor.var(int)
                binds[f"ds_digtype_{i}"] = cursor.var(int)
                binds[f"ds_digest_{i}"] = cursor.var(str, 255)
                binds[f"ds_kd_flags_{i}"] = cursor.var(int)
                binds[f"ds_kd_proto_{i}"] = cursor.var(int)
                binds[f"ds_kd_alg_{i}"] = cursor.var(int)
                binds[f"ds_kd_pubkey_{i}"] = cursor.var(str, 4000)
            for i in range(max_key_data):
                binds[f"kd_flags_{i}"] = cursor.var(int)
                binds[f"kd_proto_{i}"] = cursor.var(int)
                binds[f"kd_alg_{i}"] = cursor.var(int)
                binds[f"kd_pubkey_{i}"] = cursor.var(str, 4000)

            cursor.execute(sql, binds)
            conn.commit()

            response_code = self._extract_var(binds["response_code"], 2400)

            # Extract statuses
            statuses = []
            status_count = self._extract_var(binds["inf_status_count"], 0)
            for i in range(min(status_count, max_statuses)):
                s = self._extract_var(binds[f"st_s_{i}"], None)
                if s:
                    statuses.append({"s": s})

            # Extract contacts
            contacts = []
            contact_count = self._extract_var(binds["inf_contact_count"], 0)
            for i in range(min(contact_count, max_contacts)):
                cid = self._extract_var(binds[f"ct_id_{i}"], None)
                if cid:
                    contacts.append({
                        "id": cid,
                        "type": self._extract_var(binds[f"ct_type_{i}"], "")
                    })

            # Extract nameservers
            nameservers = []
            ns_count = self._extract_var(binds["inf_ns_count"], 0)
            for i in range(min(ns_count, max_ns)):
                ns = self._extract_var(binds[f"ns_{i}"], None)
                if ns:
                    nameservers.append(ns)

            # Extract subordinate hosts
            sub_hosts = []
            host_count = self._extract_var(binds["inf_host_count"], 0)
            for i in range(min(host_count, max_hosts)):
                h = self._extract_var(binds[f"host_{i}"], None)
                if h:
                    sub_hosts.append(h)

            # Extract extensions
            extensions = []
            ext_count = self._extract_var(binds["inf_ext_count"], 0)
            for i in range(min(ext_count, max_extensions)):
                ext_name = self._extract_var(binds[f"ext_name_{i}"], None)
                if ext_name:
                    ext_entry = {
                        "extension": ext_name,
                        "reason": self._extract_var(binds[f"ext_reason_{i}"], ""),
                        "current_values": {}
                    }
                    # Parse pipe-delimited KV string
                    cv_str = self._extract_var(binds[f"ext_cv_{i}"], "")
                    if cv_str:
                        for pair in cv_str.split("|"):
                            if "~" in pair:
                                k, v = pair.split("~", 1)
                                ext_entry["current_values"][k] = v
                    extensions.append(ext_entry)

            # Extract DNSSEC DS data
            ds_data_list = []
            ds_count = self._extract_var(binds["inf_ds_count"], 0)
            for i in range(min(ds_count, max_ds_data)):
                keytag = self._extract_var(binds[f"ds_keytag_{i}"], None)
                if keytag is not None:
                    ds_entry = {
                        "keyTag": keytag,
                        "algorithm": self._extract_var(binds[f"ds_alg_{i}"], 0),
                        "digestType": self._extract_var(binds[f"ds_digtype_{i}"], 0),
                        "digest": self._extract_var(binds[f"ds_digest_{i}"], ""),
                    }
                    # Nested key data within DS
                    kd_flags = self._extract_var(binds[f"ds_kd_flags_{i}"], None)
                    if kd_flags is not None:
                        ds_entry["keyData"] = {
                            "flags": kd_flags,
                            "protocol": self._extract_var(binds[f"ds_kd_proto_{i}"], 0),
                            "algorithm": self._extract_var(binds[f"ds_kd_alg_{i}"], 0),
                            "publicKey": self._extract_var(binds[f"ds_kd_pubkey_{i}"], ""),
                        }
                    ds_data_list.append(ds_entry)

            # Extract DNSSEC standalone key data
            key_data_list = []
            kd_count = self._extract_var(binds["inf_kd_count"], 0)
            for i in range(min(kd_count, max_key_data)):
                flags = self._extract_var(binds[f"kd_flags_{i}"], None)
                if flags is not None:
                    key_data_list.append({
                        "flags": flags,
                        "protocol": self._extract_var(binds[f"kd_proto_{i}"], 0),
                        "algorithm": self._extract_var(binds[f"kd_alg_{i}"], 0),
                        "publicKey": self._extract_var(binds[f"kd_pubkey_{i}"], ""),
                    })

            cursor.close()

            return {
                "response_code": response_code,
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "name": self._extract_var(binds["inf_name"], ""),
                "roid": self._extract_var(binds["inf_roid"], ""),
                "registrant": self._extract_var(binds["inf_registrant"], ""),
                "clID": self._extract_var(binds["inf_clid"], ""),
                "crID": self._extract_var(binds["inf_crid"], ""),
                "crDate": self._extract_var(binds["inf_crdate"], None),
                "upID": self._extract_var(binds["inf_upid"], None),
                "upDate": self._extract_var(binds["inf_update"], None),
                "exDate": self._extract_var(binds["inf_exdate"], None),
                "trDate": self._extract_var(binds["inf_trdate"], None),
                "authInfo": self._extract_var(binds["inf_authinfo"], None),
                "statuses": statuses,
                "contacts": contacts,
                "nameservers": nameservers,
                "hosts": sub_hosts,
                "extensions": extensions,
                "idn_userform": self._extract_var(binds["inf_idn_userform"], None),
                "idn_canonical": self._extract_var(binds["inf_idn_canonical"], None),
                "idn_language": self._extract_var(binds["inf_idn_lang"], None),
                "dnssec_ds": ds_data_list,
                "dnssec_keys": key_data_list,
            }

    async def domain_delete(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str
    ) -> Dict[str, Any]:
        """
        Call epp_domain.domain_delete() to delete a domain.

        Returns:
            Dict with response_code, response_message, sv_trid
        """
        sql = """
            DECLARE
                l_response epp_response_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_domain.domain_delete(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    async def domain_renew(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        cur_exp_date: datetime,
        period: int,
        period_unit: str
    ) -> Dict[str, Any]:
        """
        Call epp_domain.domain_renew() to renew a domain.

        Returns:
            Dict with response_code, response_message, sv_trid, name, ex_date
        """
        sql = """
            DECLARE
                l_response epp_response_t;
                l_rname    eppcom.labeltype;
                l_exdate   DATE;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_domain.domain_renew(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    curexpdate    => :cur_exp_date,
                    period        => :period,
                    period_unit   => :period_unit,
                    response      => l_response,
                    rname         => l_rname,
                    exdate        => l_exdate
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
                :r_name := l_rname;
                :ex_date := TO_CHAR(l_exdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "cur_exp_date": cur_exp_date,
                "period": period,
                "period_unit": period_unit,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "r_name": cursor.var(str, 255),
                "ex_date": cursor.var(str, 30)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "name": self._extract_var(binds["r_name"], name),
                "ex_date": self._extract_var(binds["ex_date"], None)
            }

    async def domain_transfer(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        op: str,
        name: str,
        period: Optional[int] = None,
        period_unit: Optional[str] = None,
        auth_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Call epp_domain.domain_transfer() for transfer operations.

        Args:
            op: Transfer operation (request, approve, reject, cancel, query)

        Returns:
            Dict with response and transfer data
        """
        authinfo_literal = (
            f"epp_authinfo_t('{self._escape_sql(auth_info)}', NULL)"
            if auth_info else "epp_authinfo_t()"
        )

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_trndata  epp_dom_trndata_t;
                l_authinfo epp_authinfo_t := {authinfo_literal};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_domain.domain_transfer(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    op            => :op,
                    name          => :name,
                    period        => :period,
                    period_unit   => :period_unit,
                    authinfo      => l_authinfo,
                    response      => l_response,
                    trndata       => l_trndata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;

                IF l_trndata IS NOT NULL THEN
                    :trn_name := l_trndata.name;
                    :trn_status := l_trndata.status;
                    :trn_reid := l_trndata.reid;
                    :trn_redate := TO_CHAR(l_trndata.redate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :trn_acid := l_trndata.acid;
                    :trn_acdate := TO_CHAR(l_trndata.acdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :trn_exdate := TO_CHAR(l_trndata.exdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                END IF;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "op": op,
                "name": name,
                "period": period,
                "period_unit": period_unit or "y",
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "trn_name": cursor.var(str, 255),
                "trn_status": cursor.var(str, 20),
                "trn_reid": cursor.var(str, 16),
                "trn_redate": cursor.var(str, 30),
                "trn_acid": cursor.var(str, 16),
                "trn_acdate": cursor.var(str, 30),
                "trn_exdate": cursor.var(str, 30)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "name": self._extract_var(binds["trn_name"], name),
                "trStatus": self._extract_var(binds["trn_status"], ""),
                "reID": self._extract_var(binds["trn_reid"], ""),
                "reDate": self._extract_var(binds["trn_redate"], None),
                "acID": self._extract_var(binds["trn_acid"], ""),
                "acDate": self._extract_var(binds["trn_acdate"], None),
                "exDate": self._extract_var(binds["trn_exdate"], None)
            }

    async def domain_update(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        add_ns: Optional[List[str]] = None,
        rem_ns: Optional[List[str]] = None,
        add_contacts: Optional[List[Dict[str, str]]] = None,
        rem_contacts: Optional[List[Dict[str, str]]] = None,
        add_statuses: Optional[List[str]] = None,
        rem_statuses: Optional[List[str]] = None,
        chg_registrant: Optional[str] = None,
        chg_authinfo: Optional[str] = None,
        extensions: Optional[List[Dict[str, Any]]] = None,
        expire_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Call epp_domain.domain_update() to update a domain.

        Returns:
            Dict with response_code, response_message, sv_trid
        """
        # Build add fields
        add_ns_lit = self._build_string_list_literal(add_ns) if add_ns else "epp_hos_list_t()"
        add_contacts_lit = self._build_contact_list_literal(add_contacts) if add_contacts else "epp_dom_contact_list_t()"
        add_statuses_lit = self._build_status_list_literal(add_statuses) if add_statuses else "epp_status_list_t()"

        # Build rem fields
        rem_ns_lit = self._build_string_list_literal(rem_ns) if rem_ns else "epp_hos_list_t()"
        rem_contacts_lit = self._build_contact_list_literal(rem_contacts) if rem_contacts else "epp_dom_contact_list_t()"
        rem_statuses_lit = self._build_status_list_literal(rem_statuses) if rem_statuses else "epp_status_list_t()"

        # Build chg fields
        registrant_lit = f"eppcom_clid_t('{self._escape_sql(chg_registrant)}')" if chg_registrant else "NULL"
        authinfo_lit = f"epp_authinfo_t('{self._escape_sql(chg_authinfo)}', NULL)" if chg_authinfo else "epp_authinfo_t()"

        # Extensions
        extensions_lit = self._build_extension_list_literal(extensions) if extensions else "extension_list_t()"

        sql = f"""
            DECLARE
                l_response   epp_response_t;
                l_add        epp_dom_add_rem_t := epp_dom_add_rem_t(
                                 {add_ns_lit}, {add_contacts_lit}, {add_statuses_lit}, NULL, NULL
                             );
                l_rem        epp_dom_add_rem_t := epp_dom_add_rem_t(
                                 {rem_ns_lit}, {rem_contacts_lit}, {rem_statuses_lit}, NULL, NULL
                             );
                l_chg        epp_dom_chg_t := epp_dom_chg_t(
                                 {registrant_lit}, {authinfo_lit}, NULL
                             );
                l_extensions extension_list_t := {extensions_lit};
                l_code       NUMBER;
                l_msg        VARCHAR2(4000);
                l_svtrid     VARCHAR2(64);
            BEGIN
                epp_domain.domain_update(
                    p_connection_id => :connection_id,
                    p_session_id    => :session_id,
                    p_cltrid        => :cltrid,
                    p_name          => :name,
                    p_add_fields    => l_add,
                    p_rem_fields    => l_rem,
                    p_chg_fields    => l_chg,
                    p_extensions    => l_extensions,
                    p_expire_date   => :expire_date,
                    p_response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "expire_date": expire_date,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    # ========================================================================
    # Helper methods for building Oracle type literals
    # ========================================================================

    def _escape_sql(self, value: str) -> str:
        """Escape single quotes in SQL string literals."""
        if value is None:
            return ""
        return str(value).replace("'", "''")

    def _extract_var(self, var, default=None):
        """Extract value from oracledb cursor variable."""
        val = var.getvalue() if hasattr(var, 'getvalue') else var
        if isinstance(val, list):
            val = val[0] if val else None
        return val if val is not None else default

    def _build_urn_list_literal(self, uris: Optional[List[str]]) -> str:
        """Build urn_list_t constructor literal."""
        if not uris:
            return "urn_list_t()"
        items = ", ".join(f"'{self._escape_sql(u)}'" for u in uris)
        return f"urn_list_t({items})"

    def _build_string_list_literal(self, items: Optional[List[str]]) -> str:
        """Build a VARCHAR2 table constructor literal for epp_hos_list_t."""
        if not items:
            return "epp_hos_list_t()"
        escaped = ", ".join(f"'{self._escape_sql(s)}'" for s in items)
        return f"epp_hos_list_t({escaped})"

    def _build_typed_string_list(self, type_name: str, items: Optional[List[str]]) -> str:
        """Build a VARCHAR2 table constructor literal for a specific Oracle type."""
        if not items:
            return f"{type_name}()"
        escaped = ", ".join(f"'{self._escape_sql(s)}'" for s in items)
        return f"{type_name}({escaped})"

    def _build_contact_list_literal(self, contacts: Optional[List[Dict[str, str]]]) -> str:
        """Build epp_dom_contact_list_t constructor literal."""
        if not contacts:
            return "epp_dom_contact_list_t()"
        items = []
        for c in contacts:
            cid = self._escape_sql(c.get("id", ""))
            ctype = self._escape_sql(c.get("type", ""))
            items.append(f"epp_dom_contact_t('{cid}', '{ctype}')")
        return f"epp_dom_contact_list_t({', '.join(items)})"

    def _build_status_list_literal(self, statuses) -> str:
        """Build epp_status_list_t constructor literal.

        Args:
            statuses: List of status dicts {"s": "clientHold", "lang": "en", "reason": "text"}
                     or list of plain strings ["clientHold"]
        """
        if not statuses:
            return "epp_status_list_t()"
        items = []
        for s in statuses:
            if isinstance(s, dict):
                value = self._escape_sql(s.get("s", ""))
                lang = s.get("lang")
                reason = s.get("reason")
                lang_lit = f"'{self._escape_sql(lang)}'" if lang else "NULL"
                reason_lit = f"'{self._escape_sql(reason)}'" if reason else "NULL"
                items.append(f"epp_status_t('{value}', {lang_lit}, {reason_lit})")
            else:
                items.append(f"epp_status_t('{self._escape_sql(s)}', NULL, NULL)")
        return f"epp_status_list_t({', '.join(items)})"

    def _build_extension_list_literal(self, extensions: Optional[List[Dict[str, Any]]]) -> str:
        """Build extension_list_t constructor literal."""
        if not extensions:
            return "extension_list_t()"
        items = []
        for ext in extensions:
            ext_name = self._escape_sql(ext.get("extension", ""))
            reason = self._escape_sql(ext.get("reason", ""))

            # Build key_value_list_t for current_values and new_values
            current_kv = self._build_kv_list_literal(ext.get("current_values"))
            new_kv = self._build_kv_list_literal(ext.get("new_values"))

            items.append(
                f"extension_t('{ext_name}', {current_kv}, {new_kv}, '{reason}')"
            )
        return f"extension_list_t({', '.join(items)})"

    def _build_kv_list_literal(self, kv_pairs: Optional[Dict[str, str]]) -> str:
        """Build key_value_list_t constructor literal."""
        if not kv_pairs:
            return "key_value_list_t()"
        items = []
        for k, v in kv_pairs.items():
            items.append(f"key_value_t('{self._escape_sql(k)}', '{self._escape_sql(v)}')")
        return f"key_value_list_t({', '.join(items)})"

    def _build_dnssec_literal(self, dnssec: Optional[Dict[str, Any]]) -> str:
        """Build dnssec_request_t constructor literal."""
        if not dnssec:
            return "NULL"

        urgent = dnssec.get("urgent", 0) or 0
        remove_all = dnssec.get("remove_all", 0) or 0
        max_sig_life = dnssec.get("maxSigLife") or "NULL"

        # Build DS data list
        ds_data = dnssec.get("dsData", [])
        if ds_data:
            ds_items = []
            for ds in ds_data:
                keytag = ds.get("keyTag", 0)
                alg = ds.get("algorithm", 0)
                digest_type = ds.get("digestType", 0)
                digest = self._escape_sql(ds.get("digest", ""))

                # Key data within DS data
                kd = ds.get("keyData")
                if kd:
                    kd_lit = (
                        f"dnssec_keydata_t({kd.get('flags', 0)}, {kd.get('protocol', 0)}, "
                        f"{kd.get('algorithm', 0)}, '{self._escape_sql(kd.get('publicKey', ''))}', NULL)"
                    )
                else:
                    kd_lit = "NULL"

                ds_items.append(
                    f"dnssec_ds_data_t({keytag}, {alg}, {digest_type}, '{digest}', {kd_lit}, NULL, NULL)"
                )
            ds_literal = f"dnssec_ds_data_list_t({', '.join(ds_items)})"
        else:
            ds_literal = "dnssec_ds_data_list_t()"

        # Build key data list
        key_data = dnssec.get("keyData", [])
        if key_data:
            kd_items = []
            for kd in key_data:
                kd_items.append(
                    f"dnssec_keydata_t({kd.get('flags', 0)}, {kd.get('protocol', 0)}, "
                    f"{kd.get('algorithm', 0)}, '{self._escape_sql(kd.get('publicKey', ''))}', NULL)"
                )
            kd_literal = f"dnssec_keydata_list_t({', '.join(kd_items)})"
        else:
            kd_literal = "dnssec_keydata_list_t()"

        return f"dnssec_request_t({urgent}, {remove_all}, {max_sig_life}, {ds_literal}, {kd_literal})"

    def _build_addr_list_literal(self, addrs: Optional[List[Dict[str, str]]]) -> str:
        """Build epp_addr_list_t constructor literal for host IP addresses."""
        if not addrs:
            return "epp_addr_list_t()"
        items = []
        for a in addrs:
            address = self._escape_sql(a.get("addr", ""))
            ip_type = self._escape_sql(a.get("ip", "v4"))
            items.append(f"epp_addr_t('{address}', '{ip_type}')")
        return f"epp_addr_list_t({', '.join(items)})"

    def _build_e164_literal(self, number: Optional[str], ext: Optional[str] = None) -> str:
        """Build epp_e164_t constructor literal for voice/fax."""
        if not number:
            return "epp_e164_t(NULL, NULL)"
        num_lit = f"'{self._escape_sql(number)}'"
        ext_lit = f"'{self._escape_sql(ext)}'" if ext else "NULL"
        return f"epp_e164_t({num_lit}, {ext_lit})"

    def _build_postalinfo_literal(self, postal: Optional[Dict[str, Any]]) -> str:
        """Build epp_postalinfo_t constructor literal for contact create."""
        if not postal:
            return "NULL"
        name = f"'{self._escape_sql(postal.get('name', ''))}'" if postal.get('name') else "NULL"
        org = f"'{self._escape_sql(postal.get('org', ''))}'" if postal.get('org') else "NULL"
        streets = postal.get("street", [])
        if isinstance(streets, str):
            streets = [streets]
        s1 = f"'{self._escape_sql(streets[0])}'" if len(streets) > 0 else "NULL"
        s2 = f"'{self._escape_sql(streets[1])}'" if len(streets) > 1 else "NULL"
        s3 = f"'{self._escape_sql(streets[2])}'" if len(streets) > 2 else "NULL"
        city = f"'{self._escape_sql(postal.get('city', ''))}'" if postal.get('city') else "NULL"
        state = f"'{self._escape_sql(postal.get('sp', ''))}'" if postal.get('sp') else "NULL"
        pc = f"'{self._escape_sql(postal.get('pc', ''))}'" if postal.get('pc') else "NULL"
        cc = f"'{self._escape_sql(postal.get('cc', ''))}'" if postal.get('cc') else "NULL"
        return f"epp_postalinfo_t({name}, {org}, {s1}, {s2}, {s3}, {city}, {state}, {pc}, {cc})"

    def _build_chg_postalinfo_literal(self, postal: Optional[Dict[str, Any]]) -> str:
        """Build epp_chg_postalinfo_t constructor literal for contact update."""
        if not postal:
            return "NULL"
        name = f"epp_postalline_t('{self._escape_sql(postal['name'])}')" if postal.get('name') else "NULL"
        org = f"epp_postalline_t('{self._escape_sql(postal['org'])}')" if postal.get('org') else "NULL"
        streets = postal.get("street", [])
        if isinstance(streets, str):
            streets = [streets]
        s1 = f"'{self._escape_sql(streets[0])}'" if len(streets) > 0 else "NULL"
        s2 = f"'{self._escape_sql(streets[1])}'" if len(streets) > 1 else "NULL"
        s3 = f"'{self._escape_sql(streets[2])}'" if len(streets) > 2 else "NULL"
        city = f"'{self._escape_sql(postal.get('city', ''))}'" if postal.get('city') else "NULL"
        state = f"'{self._escape_sql(postal.get('sp', ''))}'" if postal.get('sp') else "NULL"
        pc = f"'{self._escape_sql(postal.get('pc', ''))}'" if postal.get('pc') else "NULL"
        cc = f"'{self._escape_sql(postal.get('cc', ''))}'" if postal.get('cc') else "NULL"
        addr = f"epp_con_addr_t({s1}, {s2}, {s3}, {city}, {state}, {pc}, {cc})"
        return f"epp_chg_postalinfo_t({name}, {org}, {addr})"

    def _build_authinfo_literal(self, pw: Optional[str]) -> str:
        """Build epp_authinfo_t constructor literal."""
        if not pw:
            return "epp_authinfo_t()"
        return f"epp_authinfo_t('{self._escape_sql(pw)}', NULL)"

    # ========================================================================
    # Host Operations (epp_host package)
    # ========================================================================

    async def host_check(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        hostnames: List[str]
    ) -> Dict[str, Any]:
        """Call epp_host.host_check() to check host availability."""
        hosts_literal = self._build_string_list_literal(hostnames)
        max_results = min(len(hostnames), 20)

        result_vars = []
        for i in range(max_results):
            result_vars.append(f"""
                IF l_chkdata IS NOT NULL AND l_chkdata.COUNT >= {i + 1} THEN
                    :name_{i} := l_chkdata({i + 1}).name;
                    :avail_{i} := l_chkdata({i + 1}).avail;
                    :reason_{i} := l_chkdata({i + 1}).reason;
                END IF;
            """)

        result_extraction = "\n".join(result_vars)

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_chkdata  epp_hos_chkdata_t;
                l_hosts    epp_hos_list_t := {hosts_literal};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_host.host_check(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    hosts         => l_hosts,
                    response      => l_response,
                    chkdata       => l_chkdata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
                :result_count := CASE WHEN l_chkdata IS NOT NULL THEN l_chkdata.COUNT ELSE 0 END;

                {result_extraction}
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "result_count": cursor.var(int)
            }
            for i in range(max_results):
                binds[f"name_{i}"] = cursor.var(str, 255)
                binds[f"avail_{i}"] = cursor.var(str, 1)
                binds[f"reason_{i}"] = cursor.var(str, 32)

            cursor.execute(sql, binds)
            conn.commit()

            response_code = self._extract_var(binds["response_code"], 2400)
            result_count = self._extract_var(binds["result_count"], 0)

            results = []
            for i in range(min(result_count, max_results)):
                name = self._extract_var(binds[f"name_{i}"], "")
                avail = self._extract_var(binds[f"avail_{i}"], "0")
                reason = self._extract_var(binds[f"reason_{i}"], None)
                results.append({
                    "name": name,
                    "avail": avail == "1",
                    "reason": reason
                })

            cursor.close()

            return {
                "response_code": response_code,
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "results": results
            }

    async def host_create(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        addresses: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """Call epp_host.host_create() to create a new host."""
        addr_literal = self._build_addr_list_literal(addresses)

        sql = f"""
            DECLARE
                l_response     epp_response_t;
                l_cre_response epp_hos_cre_response_t;
                l_addr         epp_addr_list_t := {addr_literal};
                l_code         NUMBER;
                l_msg          VARCHAR2(4000);
                l_svtrid       VARCHAR2(64);
            BEGIN
                epp_host.host_create(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    addr          => l_addr,
                    response      => l_response,
                    cre_response  => l_cre_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;

                IF l_cre_response IS NOT NULL THEN
                    :cr_name := l_cre_response.dns_form;
                    :cr_date := TO_CHAR(l_cre_response.crdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                END IF;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "cr_name": cursor.var(str, 255),
                "cr_date": cursor.var(str, 30)
            }

            try:
                cursor.execute(sql, binds)
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"epp_host.host_create() failed: {e}")
                raise

            result = {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "cr_name": self._extract_var(binds["cr_name"], name),
                "cr_date": self._extract_var(binds["cr_date"], None),
            }
            cursor.close()

            logger.info(
                f"epp_host.host_create({name}) returned code={result['response_code']}"
            )
            return result

    async def host_info(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str
    ) -> Dict[str, Any]:
        """Call epp_host.host_info() to get host information."""
        max_statuses = 10
        max_addrs = 13

        status_vars = []
        for i in range(max_statuses):
            status_vars.append(f"""
                IF l_infdata.status IS NOT NULL AND l_infdata.status.COUNT >= {i + 1} THEN
                    :st_s_{i} := l_infdata.status({i + 1}).value;
                    :st_lang_{i} := l_infdata.status({i + 1}).language;
                    :st_text_{i} := l_infdata.status({i + 1}).text;
                END IF;
            """)

        addr_vars = []
        for i in range(max_addrs):
            addr_vars.append(f"""
                IF l_infdata.addr IS NOT NULL AND l_infdata.addr.COUNT >= {i + 1} THEN
                    :addr_ip_{i} := l_infdata.addr({i + 1}).ip;
                    :addr_addr_{i} := l_infdata.addr({i + 1}).address;
                END IF;
            """)

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_infdata  epp_hos_infdata_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_host.host_info(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    response      => l_response,
                    infdata       => l_infdata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;

                IF l_infdata IS NOT NULL THEN
                    :inf_name := l_infdata.name;
                    :inf_roid := l_infdata.roid;
                    :inf_clid := l_infdata.clid;
                    :inf_crid := l_infdata.crid;
                    :inf_crdate := TO_CHAR(l_infdata.crdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :inf_upid := l_infdata.upid;
                    :inf_update := TO_CHAR(l_infdata.up_date, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :inf_trdate := TO_CHAR(l_infdata.trdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :status_count := CASE WHEN l_infdata.status IS NOT NULL THEN l_infdata.status.COUNT ELSE 0 END;
                    :addr_count := CASE WHEN l_infdata.addr IS NOT NULL THEN l_infdata.addr.COUNT ELSE 0 END;

                    {"".join(status_vars)}
                    {"".join(addr_vars)}
                END IF;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "inf_name": cursor.var(str, 255),
                "inf_roid": cursor.var(str, 89),
                "inf_clid": cursor.var(str, 16),
                "inf_crid": cursor.var(str, 16),
                "inf_crdate": cursor.var(str, 30),
                "inf_upid": cursor.var(str, 16),
                "inf_update": cursor.var(str, 30),
                "inf_trdate": cursor.var(str, 30),
                "status_count": cursor.var(int),
                "addr_count": cursor.var(int),
            }
            for i in range(max_statuses):
                binds[f"st_s_{i}"] = cursor.var(str, 24)
                binds[f"st_lang_{i}"] = cursor.var(str, 20)
                binds[f"st_text_{i}"] = cursor.var(str, 100)
            for i in range(max_addrs):
                binds[f"addr_ip_{i}"] = cursor.var(str, 2)
                binds[f"addr_addr_{i}"] = cursor.var(str, 45)

            cursor.execute(sql, binds)
            conn.commit()

            response_code = self._extract_var(binds["response_code"], 2400)

            statuses = []
            status_count = self._extract_var(binds["status_count"], 0)
            for i in range(min(status_count, max_statuses)):
                s = self._extract_var(binds[f"st_s_{i}"], None)
                if s:
                    statuses.append({
                        "s": s,
                        "lang": self._extract_var(binds[f"st_lang_{i}"], None),
                        "reason": self._extract_var(binds[f"st_text_{i}"], None)
                    })

            addrs = []
            addr_count = self._extract_var(binds["addr_count"], 0)
            for i in range(min(addr_count, max_addrs)):
                addr = self._extract_var(binds[f"addr_addr_{i}"], None)
                if addr:
                    addrs.append({
                        "addr": addr,
                        "ip": self._extract_var(binds[f"addr_ip_{i}"], "v4")
                    })

            cursor.close()

            return {
                "response_code": response_code,
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "name": self._extract_var(binds["inf_name"], ""),
                "roid": self._extract_var(binds["inf_roid"], ""),
                "statuses": statuses,
                "addrs": addrs,
                "clID": self._extract_var(binds["inf_clid"], ""),
                "crID": self._extract_var(binds["inf_crid"], ""),
                "crDate": self._extract_var(binds["inf_crdate"], None),
                "upID": self._extract_var(binds["inf_upid"], None),
                "upDate": self._extract_var(binds["inf_update"], None),
                "trDate": self._extract_var(binds["inf_trdate"], None),
            }

    async def host_update(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        add_addresses: Optional[List[Dict[str, str]]] = None,
        rem_addresses: Optional[List[Dict[str, str]]] = None,
        add_statuses: Optional[List] = None,
        rem_statuses: Optional[List] = None,
        new_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Call epp_host.host_update() to update a host."""
        add_addr_lit = self._build_addr_list_literal(add_addresses)
        add_status_lit = self._build_status_list_literal(add_statuses) if add_statuses else "epp_status_list_t()"
        rem_addr_lit = self._build_addr_list_literal(rem_addresses)
        rem_status_lit = self._build_status_list_literal(rem_statuses) if rem_statuses else "epp_status_list_t()"

        if new_name:
            chg_lit = f"epp_hos_chg_t(eppcom_label_t('{self._escape_sql(new_name)}'))"
        else:
            chg_lit = "epp_hos_chg_t(NULL)"

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_add      epp_hos_add_rem_t := epp_hos_add_rem_t({add_addr_lit}, {add_status_lit});
                l_rem      epp_hos_add_rem_t := epp_hos_add_rem_t({rem_addr_lit}, {rem_status_lit});
                l_chg      epp_hos_chg_t := {chg_lit};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_host.host_update(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    add_fields    => l_add,
                    rem_fields    => l_rem,
                    chg_fields    => l_chg,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    async def host_delete(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str
    ) -> Dict[str, Any]:
        """Call epp_host.host_delete() to delete a host."""
        sql = """
            DECLARE
                l_response epp_response_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_host.host_delete(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    # ========================================================================
    # Contact Operations (epp_contact package)
    # ========================================================================

    async def contact_check(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        contact_ids: List[str]
    ) -> Dict[str, Any]:
        """Call epp_contact.contact_check() to check contact availability."""
        contacts_literal = self._build_typed_string_list("epp_con_list_t", contact_ids)
        max_results = min(len(contact_ids), 20)

        result_vars = []
        for i in range(max_results):
            result_vars.append(f"""
                IF l_chkdata IS NOT NULL AND l_chkdata.COUNT >= {i + 1} THEN
                    :id_{i} := l_chkdata({i + 1}).id;
                    :avail_{i} := l_chkdata({i + 1}).avail;
                    :reason_{i} := l_chkdata({i + 1}).reason;
                END IF;
            """)

        result_extraction = "\n".join(result_vars)

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_chkdata  epp_con_chkdata_t;
                l_contacts epp_con_list_t := {contacts_literal};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_contact.contact_check(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    contacts      => l_contacts,
                    response      => l_response,
                    chkdata       => l_chkdata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
                :result_count := CASE WHEN l_chkdata IS NOT NULL THEN l_chkdata.COUNT ELSE 0 END;

                {result_extraction}
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "result_count": cursor.var(int)
            }
            for i in range(max_results):
                binds[f"id_{i}"] = cursor.var(str, 32)
                binds[f"avail_{i}"] = cursor.var(str, 1)
                binds[f"reason_{i}"] = cursor.var(str, 32)

            cursor.execute(sql, binds)
            conn.commit()

            response_code = self._extract_var(binds["response_code"], 2400)
            result_count = self._extract_var(binds["result_count"], 0)

            results = []
            for i in range(min(result_count, max_results)):
                cid = self._extract_var(binds[f"id_{i}"], "")
                avail = self._extract_var(binds[f"avail_{i}"], "0")
                reason = self._extract_var(binds[f"reason_{i}"], None)
                results.append({
                    "id": cid,
                    "avail": avail == "1",
                    "reason": reason
                })

            cursor.close()

            return {
                "response_code": response_code,
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "results": results
            }

    async def contact_create(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        contact_id: str,
        postalinfo_int: Optional[Dict[str, Any]] = None,
        postalinfo_loc: Optional[Dict[str, Any]] = None,
        voice: Optional[str] = None,
        voice_ext: Optional[str] = None,
        fax: Optional[str] = None,
        fax_ext: Optional[str] = None,
        email: str = "",
        auth_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """Call epp_contact.contact_create() to create a new contact."""
        pi_int_lit = self._build_postalinfo_literal(postalinfo_int)
        pi_loc_lit = self._build_postalinfo_literal(postalinfo_loc)
        voice_lit = self._build_e164_literal(voice, voice_ext)
        fax_lit = self._build_e164_literal(fax, fax_ext)
        authinfo_lit = self._build_authinfo_literal(auth_info)

        sql = f"""
            DECLARE
                l_response       epp_response_t;
                l_postalinfo_int epp_postalinfo_t := {pi_int_lit};
                l_postalinfo_loc epp_postalinfo_t := {pi_loc_lit};
                l_voice          epp_e164_t := {voice_lit};
                l_fax            epp_e164_t := {fax_lit};
                l_authinfo       epp_authinfo_t := {authinfo_lit};
                l_crid           VARCHAR2(16);
                l_crdate         DATE;
                l_code           NUMBER;
                l_msg            VARCHAR2(4000);
                l_svtrid         VARCHAR2(64);
            BEGIN
                epp_contact.contact_create(
                    connection_id  => :connection_id,
                    session_id     => :session_id,
                    cltrid         => :cltrid,
                    id             => :contact_id,
                    postalinfo_int => l_postalinfo_int,
                    postalinfo_loc => l_postalinfo_loc,
                    voice          => l_voice,
                    fax            => l_fax,
                    email          => :email,
                    authinfo       => l_authinfo,
                    response       => l_response,
                    crid           => l_crid,
                    crdate         => l_crdate
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
                :cr_id := l_crid;
                :cr_date := TO_CHAR(l_crdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "contact_id": contact_id,
                "email": email or "",
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "cr_id": cursor.var(str, 16),
                "cr_date": cursor.var(str, 30)
            }

            try:
                cursor.execute(sql, binds)
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"epp_contact.contact_create() failed: {e}")
                raise

            result = {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "cr_id": self._extract_var(binds["cr_id"], contact_id),
                "cr_date": self._extract_var(binds["cr_date"], None),
            }
            cursor.close()

            logger.info(
                f"epp_contact.contact_create({contact_id}) returned code={result['response_code']}"
            )
            return result

    async def contact_info(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        contact_id: str,
        auth_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """Call epp_contact.contact_info() to get contact information."""
        authinfo_lit = self._build_authinfo_literal(auth_info)
        max_statuses = 10

        status_vars = []
        for i in range(max_statuses):
            status_vars.append(f"""
                IF l_infdata.status IS NOT NULL AND l_infdata.status.COUNT >= {i + 1} THEN
                    :st_s_{i} := l_infdata.status({i + 1}).value;
                    :st_lang_{i} := l_infdata.status({i + 1}).language;
                    :st_text_{i} := l_infdata.status({i + 1}).text;
                END IF;
            """)

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_infdata  epp_con_infdata_t;
                l_authinfo epp_authinfo_t := {authinfo_lit};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_contact.contact_info(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    id            => :contact_id,
                    authinfo      => l_authinfo,
                    response      => l_response,
                    infdata       => l_infdata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;

                IF l_infdata IS NOT NULL THEN
                    :inf_id := l_infdata.id;
                    :inf_roid := l_infdata.roid;
                    :inf_email := l_infdata.email;
                    :inf_clid := l_infdata.clid;
                    :inf_crid := l_infdata.crid;
                    :inf_crdate := TO_CHAR(l_infdata.crdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :inf_upid := l_infdata.upid;
                    :inf_update := TO_CHAR(l_infdata.up_date, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :inf_trdate := TO_CHAR(l_infdata.trdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');

                    IF l_infdata.voice IS NOT NULL THEN
                        :inf_voice := l_infdata.voice.string;
                        :inf_voice_ext := l_infdata.voice.x;
                    END IF;

                    IF l_infdata.fax IS NOT NULL THEN
                        :inf_fax := l_infdata.fax.string;
                        :inf_fax_ext := l_infdata.fax.x;
                    END IF;

                    IF l_infdata.authinfo IS NOT NULL THEN
                        :inf_authinfo := l_infdata.authinfo.pw;
                    END IF;

                    :status_count := CASE WHEN l_infdata.status IS NOT NULL THEN l_infdata.status.COUNT ELSE 0 END;
                    {"".join(status_vars)}

                    -- PostalInfo INT
                    :inf_has_pi_int := 0;
                    IF l_infdata.postalinfo_int IS NOT NULL AND l_infdata.postalinfo_int.name IS NOT NULL THEN
                        :inf_has_pi_int := 1;
                        :inf_pi_int_name := l_infdata.postalinfo_int.name;
                        :inf_pi_int_org := l_infdata.postalinfo_int.org;
                        :inf_pi_int_s1 := l_infdata.postalinfo_int.street1;
                        :inf_pi_int_s2 := l_infdata.postalinfo_int.street2;
                        :inf_pi_int_s3 := l_infdata.postalinfo_int.street3;
                        :inf_pi_int_city := l_infdata.postalinfo_int.city;
                        :inf_pi_int_sp := l_infdata.postalinfo_int.state;
                        :inf_pi_int_pc := l_infdata.postalinfo_int.postcode;
                        :inf_pi_int_cc := l_infdata.postalinfo_int.country;
                    END IF;

                    -- PostalInfo LOC
                    :inf_has_pi_loc := 0;
                    IF l_infdata.postalinfo_loc IS NOT NULL AND l_infdata.postalinfo_loc.name IS NOT NULL THEN
                        :inf_has_pi_loc := 1;
                        :inf_pi_loc_name := l_infdata.postalinfo_loc.name;
                        :inf_pi_loc_org := l_infdata.postalinfo_loc.org;
                        :inf_pi_loc_s1 := l_infdata.postalinfo_loc.street1;
                        :inf_pi_loc_s2 := l_infdata.postalinfo_loc.street2;
                        :inf_pi_loc_s3 := l_infdata.postalinfo_loc.street3;
                        :inf_pi_loc_city := l_infdata.postalinfo_loc.city;
                        :inf_pi_loc_sp := l_infdata.postalinfo_loc.state;
                        :inf_pi_loc_pc := l_infdata.postalinfo_loc.postcode;
                        :inf_pi_loc_cc := l_infdata.postalinfo_loc.country;
                    END IF;
                END IF;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "contact_id": contact_id,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "inf_id": cursor.var(str, 16),
                "inf_roid": cursor.var(str, 89),
                "inf_email": cursor.var(str, 255),
                "inf_clid": cursor.var(str, 16),
                "inf_crid": cursor.var(str, 16),
                "inf_crdate": cursor.var(str, 30),
                "inf_upid": cursor.var(str, 16),
                "inf_update": cursor.var(str, 30),
                "inf_trdate": cursor.var(str, 30),
                "inf_voice": cursor.var(str, 17),
                "inf_voice_ext": cursor.var(str, 17),
                "inf_fax": cursor.var(str, 17),
                "inf_fax_ext": cursor.var(str, 17),
                "inf_authinfo": cursor.var(str, 255),
                "status_count": cursor.var(int),
                "inf_has_pi_int": cursor.var(int),
                "inf_pi_int_name": cursor.var(str, 255),
                "inf_pi_int_org": cursor.var(str, 255),
                "inf_pi_int_s1": cursor.var(str, 255),
                "inf_pi_int_s2": cursor.var(str, 255),
                "inf_pi_int_s3": cursor.var(str, 255),
                "inf_pi_int_city": cursor.var(str, 255),
                "inf_pi_int_sp": cursor.var(str, 255),
                "inf_pi_int_pc": cursor.var(str, 16),
                "inf_pi_int_cc": cursor.var(str, 2),
                "inf_has_pi_loc": cursor.var(int),
                "inf_pi_loc_name": cursor.var(str, 255),
                "inf_pi_loc_org": cursor.var(str, 255),
                "inf_pi_loc_s1": cursor.var(str, 255),
                "inf_pi_loc_s2": cursor.var(str, 255),
                "inf_pi_loc_s3": cursor.var(str, 255),
                "inf_pi_loc_city": cursor.var(str, 255),
                "inf_pi_loc_sp": cursor.var(str, 255),
                "inf_pi_loc_pc": cursor.var(str, 16),
                "inf_pi_loc_cc": cursor.var(str, 2),
            }
            for i in range(max_statuses):
                binds[f"st_s_{i}"] = cursor.var(str, 24)
                binds[f"st_lang_{i}"] = cursor.var(str, 20)
                binds[f"st_text_{i}"] = cursor.var(str, 100)

            cursor.execute(sql, binds)
            conn.commit()

            response_code = self._extract_var(binds["response_code"], 2400)

            statuses = []
            status_count = self._extract_var(binds["status_count"], 0)
            for i in range(min(status_count, max_statuses)):
                s = self._extract_var(binds[f"st_s_{i}"], None)
                if s:
                    statuses.append({
                        "s": s,
                        "lang": self._extract_var(binds[f"st_lang_{i}"], None),
                        "reason": self._extract_var(binds[f"st_text_{i}"], None)
                    })

            # Build postal info dicts
            def _build_postal(prefix):
                street = []
                for sk in ["s1", "s2", "s3"]:
                    sv = self._extract_var(binds[f"inf_pi_{prefix}_{sk}"], None)
                    if sv:
                        street.append(sv)
                return {
                    "name": self._extract_var(binds[f"inf_pi_{prefix}_name"], None),
                    "org": self._extract_var(binds[f"inf_pi_{prefix}_org"], None),
                    "street": street,
                    "city": self._extract_var(binds[f"inf_pi_{prefix}_city"], None),
                    "sp": self._extract_var(binds[f"inf_pi_{prefix}_sp"], None),
                    "pc": self._extract_var(binds[f"inf_pi_{prefix}_pc"], None),
                    "cc": self._extract_var(binds[f"inf_pi_{prefix}_cc"], None),
                }

            pi_int = _build_postal("int") if self._extract_var(binds["inf_has_pi_int"], 0) == 1 else None
            pi_loc = _build_postal("loc") if self._extract_var(binds["inf_has_pi_loc"], 0) == 1 else None

            cursor.close()

            return {
                "response_code": response_code,
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "id": self._extract_var(binds["inf_id"], ""),
                "roid": self._extract_var(binds["inf_roid"], ""),
                "email": self._extract_var(binds["inf_email"], ""),
                "clID": self._extract_var(binds["inf_clid"], ""),
                "crID": self._extract_var(binds["inf_crid"], ""),
                "crDate": self._extract_var(binds["inf_crdate"], None),
                "upID": self._extract_var(binds["inf_upid"], None),
                "upDate": self._extract_var(binds["inf_update"], None),
                "trDate": self._extract_var(binds["inf_trdate"], None),
                "voice": self._extract_var(binds["inf_voice"], None),
                "voice_ext": self._extract_var(binds["inf_voice_ext"], None),
                "fax": self._extract_var(binds["inf_fax"], None),
                "fax_ext": self._extract_var(binds["inf_fax_ext"], None),
                "authInfo": self._extract_var(binds["inf_authinfo"], None),
                "statuses": statuses,
                "postalInfo_int": pi_int,
                "postalInfo_loc": pi_loc,
            }

    async def contact_update(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        contact_id: str,
        add_statuses: Optional[List] = None,
        rem_statuses: Optional[List] = None,
        chg_postalinfo_int: Optional[Dict[str, Any]] = None,
        chg_postalinfo_loc: Optional[Dict[str, Any]] = None,
        chg_voice: Optional[str] = None,
        chg_voice_ext: Optional[str] = None,
        chg_fax: Optional[str] = None,
        chg_fax_ext: Optional[str] = None,
        chg_email: Optional[str] = None,
        chg_authinfo: Optional[str] = None
    ) -> Dict[str, Any]:
        """Call epp_contact.contact_update() to update a contact."""
        add_status_lit = self._build_status_list_literal(add_statuses) if add_statuses else "epp_status_list_t()"
        rem_status_lit = self._build_status_list_literal(rem_statuses) if rem_statuses else "epp_status_list_t()"

        chg_pi_int_lit = self._build_chg_postalinfo_literal(chg_postalinfo_int) if chg_postalinfo_int else "NULL"
        chg_pi_loc_lit = self._build_chg_postalinfo_literal(chg_postalinfo_loc) if chg_postalinfo_loc else "NULL"
        chg_voice_lit = self._build_e164_literal(chg_voice, chg_voice_ext) if chg_voice else "NULL"
        chg_fax_lit = self._build_e164_literal(chg_fax, chg_fax_ext) if chg_fax else "NULL"
        chg_email_lit = f"eppcom_min_token_t('{self._escape_sql(chg_email)}')" if chg_email else "NULL"
        chg_authinfo_lit = self._build_authinfo_literal(chg_authinfo) if chg_authinfo else "NULL"

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_add      epp_con_add_rem_t := epp_con_add_rem_t({add_status_lit});
                l_rem      epp_con_add_rem_t := epp_con_add_rem_t({rem_status_lit});
                l_chg      epp_con_chg_t := epp_con_chg_t(
                               {chg_pi_int_lit},
                               {chg_pi_loc_lit},
                               {chg_voice_lit},
                               {chg_fax_lit},
                               {chg_email_lit},
                               {chg_authinfo_lit},
                               NULL
                           );
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_contact.contact_update(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    id            => :contact_id,
                    add_fields    => l_add,
                    rem_fields    => l_rem,
                    chg_fields    => l_chg,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "contact_id": contact_id,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    async def contact_delete(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        contact_id: str
    ) -> Dict[str, Any]:
        """Call epp_contact.contact_delete() to delete a contact."""
        sql = """
            DECLARE
                l_response epp_response_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_contact.contact_delete(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    id            => :contact_id,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "contact_id": contact_id,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    async def contact_transfer(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        op: str,
        contact_id: str,
        auth_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """Call epp_contact.contact_transfer() for transfer operations."""
        authinfo_lit = self._build_authinfo_literal(auth_info)

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_trndata  epp_con_trndata_t;
                l_authinfo epp_authinfo_t := {authinfo_lit};
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_contact.contact_transfer(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    op            => :op,
                    id            => :contact_id,
                    authinfo      => l_authinfo,
                    response      => l_response,
                    trndata       => l_trndata
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;

                IF l_trndata IS NOT NULL THEN
                    :trn_id := l_trndata.id;
                    :trn_status := l_trndata.status;
                    :trn_reid := l_trndata.reid;
                    :trn_redate := TO_CHAR(l_trndata.redate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :trn_acid := l_trndata.acid;
                    :trn_acdate := TO_CHAR(l_trndata.acdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                END IF;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "op": op,
                "contact_id": contact_id,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "trn_id": cursor.var(str, 16),
                "trn_status": cursor.var(str, 20),
                "trn_reid": cursor.var(str, 16),
                "trn_redate": cursor.var(str, 30),
                "trn_acid": cursor.var(str, 16),
                "trn_acdate": cursor.var(str, 30)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "id": self._extract_var(binds["trn_id"], contact_id),
                "trStatus": self._extract_var(binds["trn_status"], ""),
                "reID": self._extract_var(binds["trn_reid"], ""),
                "reDate": self._extract_var(binds["trn_redate"], None),
                "acID": self._extract_var(binds["trn_acid"], ""),
                "acDate": self._extract_var(binds["trn_acdate"], None)
            }


    # ========================================================================
    # Poll Operations
    # ========================================================================

    async def poll(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        op: str,
        msgid: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Call epp.poll() for poll request/acknowledge operations.

        Args:
            op: Poll operation - 'req' or 'ack'
            msgid: Message ID to acknowledge (required for ack)

        Returns:
            Dict with response, message queue info, and optional resdata
        """
        date_fmt = 'YYYY-MM-DD"T"HH24:MI:SS".0Z"'

        sql = f"""
            DECLARE
                l_response epp_response_t;
                l_resdata  epp_poll_resdata_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp.poll(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    op            => :op,
                    msgid         => :msgid,
                    cltrid        => :cltrid,
                    response      => l_response,
                    resdata       => l_resdata
                );

                -- Extract response code/message
                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;

                -- Extract message queue info
                IF l_response.msgq IS NOT NULL THEN
                    :msgq_count := l_response.msgq.count;
                    :msgq_id := l_response.msgq.id;
                    :msgq_qdate := TO_CHAR(l_response.msgq.qdate, '{date_fmt}');
                    IF l_response.msgq.msg IS NOT NULL THEN
                        :msgq_msg := l_response.msgq.msg.string;
                        :msgq_lang := l_response.msgq.msg.lang;
                    END IF;
                END IF;

                -- Extract resdata (check each nested type for NOT NULL)
                IF l_resdata IS NOT NULL THEN
                    IF l_resdata.domain_trndata IS NOT NULL THEN
                        :resdata_type := 'domain_trndata';
                        :dom_trn_name := l_resdata.domain_trndata.name;
                        :dom_trn_status := l_resdata.domain_trndata.status;
                        :dom_trn_reid := l_resdata.domain_trndata.reid;
                        :dom_trn_redate := TO_CHAR(l_resdata.domain_trndata.redate, '{date_fmt}');
                        :dom_trn_acid := l_resdata.domain_trndata.acid;
                        :dom_trn_acdate := TO_CHAR(l_resdata.domain_trndata.acdate, '{date_fmt}');
                        :dom_trn_exdate := TO_CHAR(l_resdata.domain_trndata.exdate, '{date_fmt}');
                    ELSIF l_resdata.contact_trndata IS NOT NULL THEN
                        :resdata_type := 'contact_trndata';
                        :con_trn_id := l_resdata.contact_trndata.id;
                        :con_trn_status := l_resdata.contact_trndata.status;
                        :con_trn_reid := l_resdata.contact_trndata.reid;
                        :con_trn_redate := TO_CHAR(l_resdata.contact_trndata.redate, '{date_fmt}');
                        :con_trn_acid := l_resdata.contact_trndata.acid;
                        :con_trn_acdate := TO_CHAR(l_resdata.contact_trndata.acdate, '{date_fmt}');
                    ELSIF l_resdata.domain_pandata IS NOT NULL THEN
                        :resdata_type := 'domain_pandata';
                        IF l_resdata.domain_pandata.name IS NOT NULL THEN
                            :dom_pan_name := l_resdata.domain_pandata.name.name.value;
                            :dom_pan_result := l_resdata.domain_pandata.name.paresult;
                        END IF;
                        IF l_resdata.domain_pandata.paTRID IS NOT NULL THEN
                            :dom_pan_trid_cl := l_resdata.domain_pandata.paTRID.clTRID;
                            :dom_pan_trid_sv := l_resdata.domain_pandata.paTRID.svTRID;
                        END IF;
                        :dom_pan_date := TO_CHAR(l_resdata.domain_pandata.paDate, '{date_fmt}');
                    END IF;
                END IF;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "op": op,
                "msgid": msgid,
                "cltrid": cltrid,
                # Response
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                # Message queue
                "msgq_count": cursor.var(int),
                "msgq_id": cursor.var(int),
                "msgq_qdate": cursor.var(str, 30),
                "msgq_msg": cursor.var(str, 4000),
                "msgq_lang": cursor.var(str, 20),
                # Resdata type indicator
                "resdata_type": cursor.var(str, 30),
                # Domain transfer data
                "dom_trn_name": cursor.var(str, 255),
                "dom_trn_status": cursor.var(str, 20),
                "dom_trn_reid": cursor.var(str, 16),
                "dom_trn_redate": cursor.var(str, 30),
                "dom_trn_acid": cursor.var(str, 16),
                "dom_trn_acdate": cursor.var(str, 30),
                "dom_trn_exdate": cursor.var(str, 30),
                # Contact transfer data
                "con_trn_id": cursor.var(str, 16),
                "con_trn_status": cursor.var(str, 20),
                "con_trn_reid": cursor.var(str, 16),
                "con_trn_redate": cursor.var(str, 30),
                "con_trn_acid": cursor.var(str, 16),
                "con_trn_acdate": cursor.var(str, 30),
                # Domain pandata
                "dom_pan_name": cursor.var(str, 255),
                "dom_pan_result": cursor.var(str, 5),
                "dom_pan_trid_cl": cursor.var(str, 64),
                "dom_pan_trid_sv": cursor.var(str, 64),
                "dom_pan_date": cursor.var(str, 30),
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                # Message queue
                "msgq_count": self._extract_var(binds["msgq_count"], 0),
                "msgq_id": self._extract_var(binds["msgq_id"], None),
                "msgq_qdate": self._extract_var(binds["msgq_qdate"], None),
                "msgq_msg": self._extract_var(binds["msgq_msg"], None),
                "msgq_lang": self._extract_var(binds["msgq_lang"], None),
                # Resdata
                "resdata_type": self._extract_var(binds["resdata_type"], None),
                "dom_trn_name": self._extract_var(binds["dom_trn_name"], None),
                "dom_trn_status": self._extract_var(binds["dom_trn_status"], None),
                "dom_trn_reid": self._extract_var(binds["dom_trn_reid"], None),
                "dom_trn_redate": self._extract_var(binds["dom_trn_redate"], None),
                "dom_trn_acid": self._extract_var(binds["dom_trn_acid"], None),
                "dom_trn_acdate": self._extract_var(binds["dom_trn_acdate"], None),
                "dom_trn_exdate": self._extract_var(binds["dom_trn_exdate"], None),
                "con_trn_id": self._extract_var(binds["con_trn_id"], None),
                "con_trn_status": self._extract_var(binds["con_trn_status"], None),
                "con_trn_reid": self._extract_var(binds["con_trn_reid"], None),
                "con_trn_redate": self._extract_var(binds["con_trn_redate"], None),
                "con_trn_acid": self._extract_var(binds["con_trn_acid"], None),
                "con_trn_acdate": self._extract_var(binds["con_trn_acdate"], None),
                "dom_pan_name": self._extract_var(binds["dom_pan_name"], None),
                "dom_pan_result": self._extract_var(binds["dom_pan_result"], None),
                "dom_pan_trid_cl": self._extract_var(binds["dom_pan_trid_cl"], None),
                "dom_pan_trid_sv": self._extract_var(binds["dom_pan_trid_sv"], None),
                "dom_pan_date": self._extract_var(binds["dom_pan_date"], None),
            }

    # ========================================================================
    # AR Extension Operations (epp_arext package)
    # ========================================================================

    async def domain_undelete(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str
    ) -> Dict[str, Any]:
        """
        Call epp_arext.domain_undelete() to restore a deleted domain.

        Returns:
            Dict with response_code, response_message, sv_trid
        """
        sql = """
            DECLARE
                l_response epp_response_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_arext.domain_undelete(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    async def domain_unrenew(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        cur_exp_date: datetime
    ) -> Dict[str, Any]:
        """
        Call epp_arext.domain_unrenew() to cancel a pending renewal.

        Returns:
            Dict with response_code, response_message, sv_trid, name, ex_date
        """
        sql = """
            DECLARE
                l_response epp_response_t;
                l_rname    eppcom.labeltype;
                l_exdate   DATE;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_arext.domain_unrenew(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    curexpdate    => :cur_exp_date,
                    response      => l_response,
                    rname         => l_rname,
                    exdate        => l_exdate
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
                :r_name := l_rname;
                :ex_date := TO_CHAR(l_exdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "cur_exp_date": cur_exp_date,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "r_name": cursor.var(str, 255),
                "ex_date": cursor.var(str, 30)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "name": self._extract_var(binds["r_name"], name),
                "ex_date": self._extract_var(binds["ex_date"], None)
            }

    async def domain_policy_delete(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Call epp_arext.domain_policy_delete() to delete domain for policy violation.

        Returns:
            Dict with response_code, response_message, sv_trid
        """
        sql = """
            DECLARE
                l_response epp_response_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_arext.domain_policy_delete(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    reason        => :reason,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "reason": reason or "",
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    async def domain_policy_undelete(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str
    ) -> Dict[str, Any]:
        """
        Call epp_arext.domain_policy_undelete() to restore a policy-deleted domain.

        Returns:
            Dict with response_code, response_message, sv_trid
        """
        sql = """
            DECLARE
                l_response epp_response_t;
                l_code     NUMBER;
                l_msg      VARCHAR2(4000);
                l_svtrid   VARCHAR2(64);
            BEGIN
                epp_arext.domain_policy_undelete(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    response      => l_response
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None)
            }

    async def registrant_transfer(
        self,
        connection_id: int,
        session_id: int,
        cltrid: Optional[str],
        name: str,
        cur_exp_date: datetime,
        period: int,
        period_unit: str,
        registrant_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Call epp_arext.registrant_transfer() to transfer domain to new registrant.

        Args:
            registrant_data: Dict with 'extension', 'new_values' (dict of KV pairs), 'reason'

        Returns:
            Dict with response_code, response_message, sv_trid, name, request_date, ex_date
        """
        # Build extension_t literal for the registrant parameter
        ext_name = self._escape_sql(registrant_data.get("extension", ""))
        reason = self._escape_sql(registrant_data.get("reason", ""))
        current_kv = self._build_kv_list_literal(registrant_data.get("current_values"))
        new_kv = self._build_kv_list_literal(registrant_data.get("new_values"))
        ext_literal = f"extension_t('{ext_name}', {current_kv}, {new_kv}, '{reason}')"

        date_fmt = 'YYYY-MM-DD"T"HH24:MI:SS".0Z"'

        sql = f"""
            DECLARE
                l_response    epp_response_t;
                l_registrant  extension_t := {ext_literal};
                l_rname       eppcom.labeltype;
                l_rdate       DATE;
                l_exdate      DATE;
                l_code        NUMBER;
                l_msg         VARCHAR2(4000);
                l_svtrid      VARCHAR2(64);
            BEGIN
                epp_arext.registrant_transfer(
                    connection_id => :connection_id,
                    session_id    => :session_id,
                    cltrid        => :cltrid,
                    name          => :name,
                    curexpdate    => :cur_exp_date,
                    period        => :period,
                    period_unit   => :period_unit,
                    registrant    => l_registrant,
                    response      => l_response,
                    rname         => l_rname,
                    rdate         => l_rdate,
                    exdate        => l_exdate
                );

                IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                    l_code := l_response.result(1).code;
                    IF l_response.result(1).msg IS NOT NULL THEN
                        l_msg := l_response.result(1).msg.string;
                    END IF;
                END IF;

                IF l_response.trid IS NOT NULL THEN
                    l_svtrid := l_response.trid.svTRID;
                END IF;

                :response_code := l_code;
                :response_msg := l_msg;
                :sv_trid := l_svtrid;
                :r_name := l_rname;
                :r_date := TO_CHAR(l_rdate, '{date_fmt}');
                :ex_date := TO_CHAR(l_exdate, '{date_fmt}');
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            binds = {
                "connection_id": connection_id,
                "session_id": session_id,
                "cltrid": cltrid,
                "name": name,
                "cur_exp_date": cur_exp_date,
                "period": period,
                "period_unit": period_unit,
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
                "r_name": cursor.var(str, 255),
                "r_date": cursor.var(str, 30),
                "ex_date": cursor.var(str, 30)
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            return {
                "response_code": self._extract_var(binds["response_code"], 2400),
                "response_message": self._extract_var(binds["response_msg"], ""),
                "sv_trid": self._extract_var(binds["sv_trid"], None),
                "name": self._extract_var(binds["r_name"], name),
                "request_date": self._extract_var(binds["r_date"], None),
                "ex_date": self._extract_var(binds["ex_date"], None)
            }


# Global instance
_plsql_caller: Optional[EPPProcedureCaller] = None


async def get_plsql_caller() -> EPPProcedureCaller:
    """Get or create global PL/SQL procedure caller."""
    global _plsql_caller
    if _plsql_caller is None:
        pool = await get_pool()
        _plsql_caller = EPPProcedureCaller(pool)
    return _plsql_caller
