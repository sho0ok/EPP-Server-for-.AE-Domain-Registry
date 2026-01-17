"""
EPP CLI Main Entry Point

Command-line interface for EPP client operations.
"""

import getpass
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from epp_client import EPPClient
from epp_client.exceptions import (
    EPPAuthenticationError,
    EPPCommandError,
    EPPConnectionError,
    EPPError,
    EPPObjectExists,
    EPPObjectNotFound,
)
from epp_client.models import AEEligibility, StatusValue
from epp_cli.config import CLIConfig, create_sample_config
from epp_cli.output import OutputFormatter, print_error, print_info, print_success


# Global state for the CLI session
class CLIState:
    client: Optional[EPPClient] = None
    config: Optional[CLIConfig] = None
    formatter: Optional[OutputFormatter] = None


state = CLIState()


# =============================================================================
# Main CLI Group
# =============================================================================

@click.group()
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
@click.option("--profile", "-p", default="default", help="Config profile to use")
@click.option("--host", "-h", help="EPP server hostname")
@click.option("--port", type=int, default=700, help="EPP server port")
@click.option("--cert", type=click.Path(exists=True), help="Client certificate file")
@click.option("--key", type=click.Path(exists=True), help="Client private key file")
@click.option("--ca", type=click.Path(exists=True), help="CA certificate file")
@click.option("--client-id", "-u", help="Client/registrar ID")
@click.option("--password", "-P", help="Password (or use EPP_PASSWORD env)")
@click.option("--timeout", type=int, default=30, help="Connection timeout")
@click.option("--no-verify", is_flag=True, help="Disable server certificate verification")
@click.option("--format", "-f", type=click.Choice(["table", "json", "xml"]), default="table", help="Output format")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.version_option(version="1.0.0")
@click.pass_context
def cli(ctx, config, profile, host, port, cert, key, ca, client_id, password, timeout, no_verify, format, quiet, debug):
    """
    EPP Client CLI - Domain Registry Operations

    Connect to an EPP server and manage domains, contacts, and hosts.

    \b
    Configuration:
      Use a config file at ~/.epp/config.yaml or specify options on command line.
      Run 'epp config init' to create a sample config file.

    \b
    Examples:
      epp --host epp.registry.ae --cert client.crt --key client.key domain check example.ae
      epp -c config.yaml domain info example.ae
      epp --profile production domain create example.ae --registrant contact123
    """
    # Setup logging
    if debug:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Setup formatter
    state.formatter = OutputFormatter(format=format, quiet=quiet)

    # Load config
    loaded_config = None
    if config:
        loaded_config = CLIConfig.from_file(Path(config), profile)
    else:
        loaded_config = CLIConfig.find_and_load(profile)

    # Build final config from loaded + CLI options
    if loaded_config:
        # CLI options override config file
        final_host = host or loaded_config.server.host
        final_port = port if port != 700 else loaded_config.server.port
        final_cert = cert or loaded_config.certs.cert_file
        final_key = key or loaded_config.certs.key_file
        final_ca = ca or loaded_config.certs.ca_file
        final_client_id = client_id or loaded_config.credentials.client_id
        final_password = password or loaded_config.credentials.password
        final_timeout = timeout if timeout != 30 else loaded_config.server.timeout
        final_verify = not no_verify and loaded_config.server.verify_server
    else:
        final_host = host
        final_port = port
        final_cert = cert
        final_key = key
        final_ca = ca
        final_client_id = client_id
        final_password = password
        final_timeout = timeout
        final_verify = not no_verify

    # Check for password in environment
    if not final_password:
        import os
        final_password = os.environ.get("EPP_PASSWORD")

    # Store in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["host"] = final_host
    ctx.obj["port"] = final_port
    ctx.obj["cert"] = final_cert
    ctx.obj["key"] = final_key
    ctx.obj["ca"] = final_ca
    ctx.obj["client_id"] = final_client_id
    ctx.obj["password"] = final_password
    ctx.obj["timeout"] = final_timeout
    ctx.obj["verify"] = final_verify


def get_client(ctx) -> EPPClient:
    """
    Get or create EPP client.

    Args:
        ctx: Click context

    Returns:
        Connected and logged-in EPP client
    """
    host = ctx.obj.get("host")
    if not host:
        print_error("No server host specified. Use --host or config file.")
        sys.exit(1)

    client_id = ctx.obj.get("client_id")
    if not client_id:
        print_error("No client ID specified. Use --client-id or config file.")
        sys.exit(1)

    password = ctx.obj.get("password")
    if not password:
        password = getpass.getpass("Password: ")

    try:
        client = EPPClient(
            host=host,
            port=ctx.obj.get("port", 700),
            cert_file=ctx.obj.get("cert"),
            key_file=ctx.obj.get("key"),
            ca_file=ctx.obj.get("ca"),
            timeout=ctx.obj.get("timeout", 30),
            verify_server=ctx.obj.get("verify", True),
        )

        client.connect()
        client.login(client_id, password)

        return client

    except EPPConnectionError as e:
        print_error(f"Connection failed: {e}")
        sys.exit(1)
    except EPPAuthenticationError as e:
        print_error(f"Authentication failed: {e}")
        sys.exit(1)


# =============================================================================
# Config Commands
# =============================================================================

@cli.group()
def config():
    """Configuration management commands."""
    pass


@config.command("init")
@click.option("--path", "-p", type=click.Path(), default="~/.epp/config.yaml", help="Config file path")
def config_init(path):
    """Create sample configuration file."""
    path = Path(path).expanduser()

    # Create parent directory
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        if not click.confirm(f"{path} already exists. Overwrite?"):
            return

    sample = create_sample_config()
    path.write_text(sample)

    print_success(f"Created config file: {path}")
    print_info("Edit the file to configure your EPP connection settings.")


@config.command("show")
@click.pass_context
def config_show(ctx):
    """Show current configuration."""
    info = {
        "Host": ctx.obj.get("host") or "(not set)",
        "Port": ctx.obj.get("port"),
        "Client ID": ctx.obj.get("client_id") or "(not set)",
        "Certificate": ctx.obj.get("cert") or "(not set)",
        "Key": ctx.obj.get("key") or "(not set)",
        "CA": ctx.obj.get("ca") or "(not set)",
        "Timeout": ctx.obj.get("timeout"),
        "Verify Server": ctx.obj.get("verify"),
    }
    state.formatter.output(info)


# =============================================================================
# Session Commands
# =============================================================================

@cli.command()
@click.pass_context
def hello(ctx):
    """Send hello command and show server greeting."""
    host = ctx.obj.get("host")
    if not host:
        print_error("No server host specified. Use --host or config file.")
        sys.exit(1)

    try:
        client = EPPClient(
            host=host,
            port=ctx.obj.get("port", 700),
            cert_file=ctx.obj.get("cert"),
            key_file=ctx.obj.get("key"),
            ca_file=ctx.obj.get("ca"),
            timeout=ctx.obj.get("timeout", 30),
            verify_server=ctx.obj.get("verify", True),
        )

        greeting = client.connect()
        state.formatter.output(greeting)
        client.disconnect()

    except EPPConnectionError as e:
        print_error(f"Connection failed: {e}")
        sys.exit(1)


# =============================================================================
# Domain Commands
# =============================================================================

@cli.group()
def domain():
    """Domain management commands."""
    pass


@domain.command("check")
@click.argument("names", nargs=-1, required=True)
@click.pass_context
def domain_check(ctx, names):
    """
    Check domain availability.

    NAMES: One or more domain names to check.
    """
    client = get_client(ctx)
    try:
        result = client.domain_check(list(names))
        state.formatter.output(result.results)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("info")
@click.argument("name")
@click.option("--auth-info", "-a", help="Auth info for transfer query")
@click.pass_context
def domain_info(ctx, name, auth_info):
    """
    Get domain information.

    NAME: Domain name to query.
    """
    client = get_client(ctx)
    try:
        result = client.domain_info(name, auth_info=auth_info)
        state.formatter.output(result)
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("create")
@click.argument("name")
@click.option("--registrant", "-r", required=True, help="Registrant contact ID")
@click.option("--admin", "-a", help="Admin contact ID")
@click.option("--tech", "-t", help="Tech contact ID")
@click.option("--billing", "-b", help="Billing contact ID")
@click.option("--ns", "-n", multiple=True, help="Nameserver (can specify multiple)")
@click.option("--period", "-p", type=int, default=1, help="Registration period")
@click.option("--period-unit", type=click.Choice(["y", "m"]), default="y", help="Period unit (y=year, m=month)")
@click.option("--auth-info", help="Auth info (auto-generated if not provided)")
# AE Eligibility extension options for restricted zones (.co.ae, .gov.ae, etc.)
@click.option("--eligibility-type", help="Eligibility type (e.g., TradeLicense, Trademark)")
@click.option("--eligibility-name", help="Eligibility name (company/organization name)")
@click.option("--eligibility-id", help="Eligibility ID (license/trademark number)")
@click.option("--eligibility-id-type", help="Eligibility ID type (e.g., TradeLicense, Trademark)")
@click.option("--policy-reason", type=int, help="Policy reason (1-3)")
@click.option("--registrant-id", help="Registrant ID (e.g., Emirates ID)")
@click.option("--registrant-id-type", help="Registrant ID type (e.g., EmiratesID, Passport)")
@click.option("--registrant-name", help="Registrant name")
@click.pass_context
def domain_create(ctx, name, registrant, admin, tech, billing, ns, period, period_unit, auth_info,
                  eligibility_type, eligibility_name, eligibility_id, eligibility_id_type,
                  policy_reason, registrant_id, registrant_id_type, registrant_name):
    """
    Create a new domain.

    NAME: Domain name to create.

    For restricted zones (.co.ae, .gov.ae, .ac.ae, etc.), eligibility
    extension data may be required:

    \b
    Examples:

    \b
    # Standard .ae domain
    epp domain create example.ae --registrant contact123

    \b
    # Restricted .co.ae domain with eligibility
    epp domain create example.co.ae --registrant contact123 \\
        --eligibility-type TradeLicense \\
        --eligibility-name "Example Company LLC" \\
        --eligibility-id "123456" \\
        --eligibility-id-type TradeLicense
    """
    # Build AE eligibility extension if any eligibility options provided
    ae_eligibility = None
    if eligibility_type or eligibility_name:
        ae_eligibility = AEEligibility(
            eligibility_type=eligibility_type or "",
            eligibility_name=eligibility_name or "",
            eligibility_id=eligibility_id,
            eligibility_id_type=eligibility_id_type,
            policy_reason=policy_reason,
            registrant_id=registrant_id,
            registrant_id_type=registrant_id_type,
            registrant_name=registrant_name,
        )

    client = get_client(ctx)
    try:
        result = client.domain_create(
            name=name,
            registrant=registrant,
            admin=admin,
            tech=tech,
            billing=billing,
            nameservers=list(ns) if ns else None,
            period=period,
            period_unit=period_unit,
            auth_info=auth_info,
            ae_eligibility=ae_eligibility,
        )
        state.formatter.output(result)
        state.formatter.success(f"Domain created: {name}")
    except EPPObjectExists:
        print_error(f"Domain already exists: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("delete")
@click.argument("name")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def domain_delete(ctx, name, confirm):
    """
    Delete a domain.

    NAME: Domain name to delete.
    """
    if not confirm:
        if not click.confirm(f"Are you sure you want to delete {name}?"):
            return

    client = get_client(ctx)
    try:
        client.domain_delete(name)
        state.formatter.success(f"Domain deleted: {name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("renew")
@click.argument("name")
@click.option("--exp-date", "-e", required=True, help="Current expiry date (YYYY-MM-DD)")
@click.option("--period", "-p", type=int, default=1, help="Renewal period")
@click.option("--period-unit", type=click.Choice(["y", "m"]), default="y", help="Period unit")
@click.pass_context
def domain_renew(ctx, name, exp_date, period, period_unit):
    """
    Renew a domain.

    NAME: Domain name to renew.
    """
    client = get_client(ctx)
    try:
        result = client.domain_renew(
            name=name,
            cur_exp_date=exp_date,
            period=period,
            period_unit=period_unit,
        )
        state.formatter.output(result)
        state.formatter.success(f"Domain renewed: {name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("transfer")
@click.argument("name")
@click.argument("operation", type=click.Choice(["request", "query", "approve", "reject", "cancel"]))
@click.option("--auth-info", "-a", help="Auth info (required for request)")
@click.option("--period", "-p", type=int, help="Renewal period for transfer")
@click.pass_context
def domain_transfer(ctx, name, operation, auth_info, period):
    """
    Domain transfer operations.

    NAME: Domain name.
    OPERATION: Transfer operation (request, query, approve, reject, cancel).
    """
    client = get_client(ctx)
    try:
        if operation == "request":
            if not auth_info:
                print_error("Auth info required for transfer request")
                sys.exit(1)
            result = client.domain_transfer_request(name, auth_info, period=period)
            state.formatter.output(result)
        elif operation == "query":
            result = client.domain_transfer_query(name)
            state.formatter.output(result)
        elif operation == "approve":
            client.domain_transfer_approve(name)
            state.formatter.success(f"Transfer approved: {name}")
        elif operation == "reject":
            client.domain_transfer_reject(name)
            state.formatter.success(f"Transfer rejected: {name}")
        elif operation == "cancel":
            client.domain_transfer_cancel(name)
            state.formatter.success(f"Transfer cancelled: {name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@domain.command("update")
@click.argument("name")
@click.option("--add-ns", multiple=True, help="Add nameserver")
@click.option("--rem-ns", multiple=True, help="Remove nameserver")
@click.option("--add-status", multiple=True, help="Add status (e.g., clientHold)")
@click.option("--add-status-reason", multiple=True, help="Reason for add-status (same order as --add-status)")
@click.option("--rem-status", multiple=True, help="Remove status")
@click.option("--registrant", help="New registrant contact ID")
@click.option("--auth-info", help="New auth info")
@click.pass_context
def domain_update(ctx, name, add_ns, rem_ns, add_status, add_status_reason, rem_status, registrant, auth_info):
    """
    Update a domain.

    NAME: Domain name to update.

    Examples:

    \b
    # Add clientHold without reason
    epp domain update example.ae --add-status clientHold

    \b
    # Add clientHold with reason
    epp domain update example.ae --add-status clientHold --add-status-reason "Payment pending"

    \b
    # Multiple statuses with reasons
    epp domain update example.ae --add-status clientHold --add-status-reason "Under investigation" --add-status clientTransferProhibited --add-status-reason "Dispute"
    """
    client = get_client(ctx)
    try:
        # Build status list with optional reasons
        status_list = None
        if add_status:
            status_list = []
            reasons = list(add_status_reason) if add_status_reason else []
            for i, status in enumerate(add_status):
                if i < len(reasons) and reasons[i]:
                    status_list.append(StatusValue(status, reasons[i]))
                else:
                    status_list.append(status)

        client.domain_update(
            name=name,
            add_ns=list(add_ns) if add_ns else None,
            rem_ns=list(rem_ns) if rem_ns else None,
            add_status=status_list,
            rem_status=list(rem_status) if rem_status else None,
            new_registrant=registrant,
            new_auth_info=auth_info,
        )
        state.formatter.success(f"Domain updated: {name}")
    except EPPObjectNotFound:
        print_error(f"Domain not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Contact Commands
# =============================================================================

@cli.group()
def contact():
    """Contact management commands."""
    pass


@contact.command("check")
@click.argument("ids", nargs=-1, required=True)
@click.pass_context
def contact_check(ctx, ids):
    """
    Check contact availability.

    IDS: One or more contact IDs to check.
    """
    client = get_client(ctx)
    try:
        result = client.contact_check(list(ids))
        state.formatter.output(result.results)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("info")
@click.argument("id")
@click.option("--auth-info", "-a", help="Auth info")
@click.pass_context
def contact_info(ctx, id, auth_info):
    """
    Get contact information.

    ID: Contact ID to query.
    """
    client = get_client(ctx)
    try:
        result = client.contact_info(id, auth_info=auth_info)
        state.formatter.output(result)
    except EPPObjectNotFound:
        print_error(f"Contact not found: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("create")
@click.argument("id")
@click.option("--name", "-n", required=True, help="Contact name")
@click.option("--email", "-e", required=True, help="Email address")
@click.option("--city", "-c", required=True, help="City")
@click.option("--country", "-C", required=True, help="Country code (2-letter)")
@click.option("--org", "-o", help="Organization")
@click.option("--street", "-s", multiple=True, help="Street address (can specify multiple)")
@click.option("--state", "-S", "state_province", help="State/province")
@click.option("--postal-code", "-z", help="Postal/ZIP code")
@click.option("--voice", "-v", help="Phone number")
@click.option("--fax", "-f", help="Fax number")
@click.option("--auth-info", help="Auth info (auto-generated if not provided)")
@click.pass_context
def contact_create(ctx, id, name, email, city, country, org, street, state_province, postal_code, voice, fax, auth_info):
    """
    Create a new contact.

    ID: Contact ID to create.
    """
    client = get_client(ctx)
    try:
        result = client.contact_create(
            id=id,
            name=name,
            email=email,
            city=city,
            country_code=country,
            org=org,
            street=list(street) if street else None,
            state=state_province,
            postal_code=postal_code,
            voice=voice,
            fax=fax,
            auth_info=auth_info,
        )
        state.formatter.output(result)
        state.formatter.success(f"Contact created: {id}")
    except EPPObjectExists:
        print_error(f"Contact already exists: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("delete")
@click.argument("id")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def contact_delete(ctx, id, confirm):
    """
    Delete a contact.

    ID: Contact ID to delete.
    """
    if not confirm:
        if not click.confirm(f"Are you sure you want to delete {id}?"):
            return

    client = get_client(ctx)
    try:
        client.contact_delete(id)
        state.formatter.success(f"Contact deleted: {id}")
    except EPPObjectNotFound:
        print_error(f"Contact not found: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@contact.command("update")
@click.argument("id")
@click.option("--email", "-e", help="New email")
@click.option("--voice", "-v", help="New phone")
@click.option("--fax", "-f", help="New fax")
@click.option("--add-status", multiple=True, help="Add status")
@click.option("--rem-status", multiple=True, help="Remove status")
@click.option("--auth-info", help="New auth info")
@click.pass_context
def contact_update(ctx, id, email, voice, fax, add_status, rem_status, auth_info):
    """
    Update a contact.

    ID: Contact ID to update.
    """
    client = get_client(ctx)
    try:
        client.contact_update(
            id=id,
            new_email=email,
            new_voice=voice,
            new_fax=fax,
            add_status=list(add_status) if add_status else None,
            rem_status=list(rem_status) if rem_status else None,
            new_auth_info=auth_info,
        )
        state.formatter.success(f"Contact updated: {id}")
    except EPPObjectNotFound:
        print_error(f"Contact not found: {id}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Host Commands
# =============================================================================

@cli.group()
def host():
    """Host (nameserver) management commands."""
    pass


@host.command("check")
@click.argument("names", nargs=-1, required=True)
@click.pass_context
def host_check(ctx, names):
    """
    Check host availability.

    NAMES: One or more host names to check.
    """
    client = get_client(ctx)
    try:
        result = client.host_check(list(names))
        state.formatter.output(result.results)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@host.command("info")
@click.argument("name")
@click.pass_context
def host_info(ctx, name):
    """
    Get host information.

    NAME: Host name to query.
    """
    client = get_client(ctx)
    try:
        result = client.host_info(name)
        state.formatter.output(result)
    except EPPObjectNotFound:
        print_error(f"Host not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@host.command("create")
@click.argument("name")
@click.option("--ipv4", "-4", multiple=True, help="IPv4 address")
@click.option("--ipv6", "-6", multiple=True, help="IPv6 address")
@click.pass_context
def host_create(ctx, name, ipv4, ipv6):
    """
    Create a new host.

    NAME: Host name to create.
    """
    client = get_client(ctx)
    try:
        result = client.host_create(
            name=name,
            ipv4=list(ipv4) if ipv4 else None,
            ipv6=list(ipv6) if ipv6 else None,
        )
        state.formatter.output(result)
        state.formatter.success(f"Host created: {name}")
    except EPPObjectExists:
        print_error(f"Host already exists: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@host.command("delete")
@click.argument("name")
@click.option("--confirm", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def host_delete(ctx, name, confirm):
    """
    Delete a host.

    NAME: Host name to delete.
    """
    if not confirm:
        if not click.confirm(f"Are you sure you want to delete {name}?"):
            return

    client = get_client(ctx)
    try:
        client.host_delete(name)
        state.formatter.success(f"Host deleted: {name}")
    except EPPObjectNotFound:
        print_error(f"Host not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@host.command("update")
@click.argument("name")
@click.option("--add-ipv4", multiple=True, help="Add IPv4 address")
@click.option("--add-ipv6", multiple=True, help="Add IPv6 address")
@click.option("--rem-ipv4", multiple=True, help="Remove IPv4 address")
@click.option("--rem-ipv6", multiple=True, help="Remove IPv6 address")
@click.option("--add-status", multiple=True, help="Add status")
@click.option("--rem-status", multiple=True, help="Remove status")
@click.option("--new-name", help="Rename host")
@click.pass_context
def host_update(ctx, name, add_ipv4, add_ipv6, rem_ipv4, rem_ipv6, add_status, rem_status, new_name):
    """
    Update a host.

    NAME: Host name to update.
    """
    client = get_client(ctx)
    try:
        client.host_update(
            name=name,
            add_ipv4=list(add_ipv4) if add_ipv4 else None,
            add_ipv6=list(add_ipv6) if add_ipv6 else None,
            rem_ipv4=list(rem_ipv4) if rem_ipv4 else None,
            rem_ipv6=list(rem_ipv6) if rem_ipv6 else None,
            add_status=list(add_status) if add_status else None,
            rem_status=list(rem_status) if rem_status else None,
            new_name=new_name,
        )
        state.formatter.success(f"Host updated: {name}")
    except EPPObjectNotFound:
        print_error(f"Host not found: {name}")
        sys.exit(1)
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Poll Commands
# =============================================================================

@cli.group()
def poll():
    """Poll message commands."""
    pass


@poll.command("request")
@click.pass_context
def poll_request(ctx):
    """Request next poll message."""
    client = get_client(ctx)
    try:
        result = client.poll_request()
        if result:
            state.formatter.output(result)
        else:
            print_info("No messages in queue")
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


@poll.command("ack")
@click.argument("msg_id")
@click.pass_context
def poll_ack(ctx, msg_id):
    """
    Acknowledge poll message.

    MSG_ID: Message ID to acknowledge.
    """
    client = get_client(ctx)
    try:
        client.poll_ack(msg_id)
        state.formatter.success(f"Message acknowledged: {msg_id}")
    except EPPCommandError as e:
        print_error(f"Command failed: {e}")
        sys.exit(1)
    finally:
        client.disconnect()


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Main entry point."""
    try:
        cli()
    except EPPError as e:
        print_error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
