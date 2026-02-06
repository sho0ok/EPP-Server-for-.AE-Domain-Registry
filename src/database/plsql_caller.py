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
        Call epp.register_server() to register this EPP server.

        The old C++ EPP server called this on startup. It inserts a record
        into EPP_SERVERS with status 'A' (Active), which authorizes the
        server IP for epp.start_connection() calls.

        Args:
            server_name: Server hostname
            server_ip: Server IP address
            server_port: Server port
            supported_uris: List of supported EPP URIs
        """
        uris_literal = self._build_urn_list_literal(supported_uris)

        sql = f"""
            BEGIN
                epp.register_server(
                    server_name    => :server_name,
                    server_ip      => :server_ip,
                    server_port    => :server_port,
                    supported_uris => {uris_literal}
                );
            END;
        """

        async with self.pool.acquire() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, {
                "server_name": server_name,
                "server_ip": server_ip,
                "server_port": server_port
            })
            conn.commit()
            cursor.close()

            logger.info(
                f"epp.register_server() called: name={server_name}, "
                f"ip={server_ip}, port={server_port}"
            )

    # ========================================================================
    # EPP Connection & Session (epp package)
    # ========================================================================

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
                "client_ip": client_ip,
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

        Returns:
            Dict with domain info and response data
        """
        authinfo_literal = (
            f"epp_authinfo_t('{self._escape_sql(auth_info)}', NULL)"
            if auth_info else "epp_authinfo_t()"
        )

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
                    :inf_crdate := TO_CHAR(l_infdata.crdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :inf_upid := l_infdata.upid;
                    :inf_update := TO_CHAR(l_infdata.up_date, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :inf_exdate := TO_CHAR(l_infdata.exdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');
                    :inf_trdate := TO_CHAR(l_infdata.trdate, 'YYYY-MM-DD"T"HH24:MI:SS".0Z"');

                    IF l_infdata.authinfo IS NOT NULL THEN
                        :inf_authinfo := l_infdata.authinfo.pw;
                    END IF;

                    -- Count nameservers and contacts for subsequent retrieval
                    :inf_ns_count := CASE WHEN l_infdata.ns IS NOT NULL THEN l_infdata.ns.COUNT ELSE 0 END;
                    :inf_contact_count := CASE WHEN l_infdata.contact IS NOT NULL THEN l_infdata.contact.COUNT ELSE 0 END;
                    :inf_status_count := CASE WHEN l_infdata.status IS NOT NULL THEN l_infdata.status.COUNT ELSE 0 END;
                    :inf_host_count := CASE WHEN l_infdata.host IS NOT NULL THEN l_infdata.host.COUNT ELSE 0 END;
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
                "response_code": cursor.var(int),
                "response_msg": cursor.var(str, 4000),
                "sv_trid": cursor.var(str, 64),
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
                "inf_ns_count": cursor.var(int),
                "inf_contact_count": cursor.var(int),
                "inf_status_count": cursor.var(int),
                "inf_host_count": cursor.var(int),
            }

            cursor.execute(sql, binds)
            conn.commit()
            cursor.close()

            response_code = self._extract_var(binds["response_code"], 2400)

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

    def _build_status_list_literal(self, statuses: Optional[List[str]]) -> str:
        """Build epp_status_list_t constructor literal."""
        if not statuses:
            return "epp_status_list_t()"
        items = []
        for s in statuses:
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


# Global instance
_plsql_caller: Optional[EPPProcedureCaller] = None


async def get_plsql_caller() -> EPPProcedureCaller:
    """Get or create global PL/SQL procedure caller."""
    global _plsql_caller
    if _plsql_caller is None:
        pool = await get_pool()
        _plsql_caller = EPPProcedureCaller(pool)
    return _plsql_caller
