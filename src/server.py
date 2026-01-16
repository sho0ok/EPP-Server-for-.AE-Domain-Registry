"""
EPP Server Main Module

Asyncio-based EPP server that:
1. Listens on port 700 with TLS 1.2+
2. Accepts client connections with certificate verification
3. Sends EPP greeting on connect
4. Processes EPP commands in a loop
5. Handles disconnection gracefully
"""

import asyncio
import logging
import logging.config
import os
import signal
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from src.core.tls_handler import TLSHandler, ClientCertInfo
from src.core.frame_handler import FrameHandler, FrameReadError, FrameSizeError
from src.core.xml_processor import XMLProcessor, XMLParseError, XMLValidationError, EPPCommand
from src.core.session_manager import SessionInfo
from src.database.connection import initialize_pool, close_pool, get_pool
from src.database.repositories import get_account_repo
from src.commands.domain import get_domain_handler
from src.commands.contact import get_contact_handler
from src.commands.host import get_host_handler
from src.utils.response_builder import (
    ResponseBuilder,
    initialize_response_builder,
    get_response_builder,
)

logger = logging.getLogger("epp.server")


class EPPClientHandler:
    """
    Handles a single EPP client connection.

    Manages the connection lifecycle:
    1. TLS handshake and certificate verification
    2. Send greeting
    3. Process commands until logout or disconnect
    4. Clean up resources
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        frame_handler: FrameHandler,
        xml_processor: XMLProcessor,
        response_builder: ResponseBuilder,
        config: Dict[str, Any]
    ):
        """Initialize client handler."""
        self.reader = reader
        self.writer = writer
        self.frame_handler = frame_handler
        self.xml_processor = xml_processor
        self.response_builder = response_builder
        self.config = config

        # Connection info
        self.client_ip: str = "0.0.0.0"
        self.client_port: int = 0
        self.client_cert: Optional[ClientCertInfo] = None

        # Session state (legacy attributes for backwards compatibility)
        self.authenticated: bool = False
        self.session_id: Optional[int] = None
        self.connection_id: Optional[int] = None
        self.user_id: Optional[int] = None
        self.account_id: Optional[int] = None
        self.client_id: Optional[str] = None

        # Session info object (for command handlers)
        self.session: Optional[SessionInfo] = None

        # Extract connection info
        self._extract_connection_info()

    def _extract_connection_info(self) -> None:
        """Extract client IP and certificate info from transport."""
        from datetime import datetime

        transport = self.writer.get_extra_info("transport")
        server_ip = "0.0.0.0"
        server_port = self.config.get("server", {}).get("port", 700)

        if transport:
            peername = transport.get_extra_info("peername")
            if peername:
                self.client_ip = peername[0]
                self.client_port = peername[1]

            sockname = transport.get_extra_info("sockname")
            if sockname:
                server_ip = sockname[0]
                server_port = sockname[1]

            ssl_object = transport.get_extra_info("ssl_object")
            if ssl_object:
                self.client_cert = TLSHandler.extract_client_cert_info(ssl_object)

        # Create SessionInfo for command handlers
        self.session = SessionInfo(
            connection_id=0,  # Will be set when logged to DB
            client_ip=self.client_ip,
            client_port=self.client_port,
            server_ip=server_ip,
            server_port=server_port,
            server_name=self.config.get("epp", {}).get("server_id", "EPP Server"),
            connect_time=datetime.utcnow()
        )

        logger.info(f"Client connected: {self.client_ip}:{self.client_port}")
        if self.client_cert:
            logger.info(f"Client certificate CN: {self.client_cert.common_name}")

    async def handle(self) -> None:
        """Main client handling loop."""
        try:
            # Send greeting
            await self._send_greeting()

            # Process commands until logout or disconnect
            while True:
                try:
                    # Read next frame
                    xml_data = await self.frame_handler.read_frame(self.reader)

                    # Parse command
                    command = self.xml_processor.parse(xml_data)
                    logger.debug(f"Received command: {command.command_type}")

                    # Process command
                    response = await self._process_command(command)

                    # Send response
                    await self.frame_handler.write_frame(self.writer, response)

                    # Check for logout
                    if command.command_type == "logout":
                        logger.info(f"Client {self.client_ip} logged out")
                        break

                except asyncio.TimeoutError:
                    logger.warning(f"Read timeout for {self.client_ip}")
                    # Send timeout error and close
                    await self._send_error(2500, "Command failed; server closing connection")
                    break

                except FrameReadError as e:
                    logger.info(f"Client {self.client_ip} disconnected: {e}")
                    break

                except FrameSizeError as e:
                    logger.warning(f"Frame size error from {self.client_ip}: {e}")
                    await self._send_error(2001, str(e))
                    break

                except XMLParseError as e:
                    logger.warning(f"XML parse error from {self.client_ip}: {e}")
                    await self._send_error(2001, f"Command syntax error: {e}")

                except XMLValidationError as e:
                    logger.warning(f"XML validation error from {self.client_ip}: {e}")
                    await self._send_error(2001, f"Command syntax error: {e}")

                except Exception as e:
                    logger.exception(f"Error processing command from {self.client_ip}: {e}")
                    await self._send_error(2400, "Command failed")

        except Exception as e:
            logger.exception(f"Fatal error handling client {self.client_ip}: {e}")

        finally:
            await self._cleanup()

    async def _send_greeting(self) -> None:
        """Send EPP greeting to client."""
        greeting = self.response_builder.build_greeting()
        await self.frame_handler.write_frame(self.writer, greeting)
        logger.debug(f"Sent greeting to {self.client_ip}")

    async def _send_error(
        self,
        code: int,
        message: str,
        cl_trid: Optional[str] = None
    ) -> None:
        """Send error response to client."""
        try:
            response = self.response_builder.build_error(
                code=code,
                message=message,
                cl_trid=cl_trid
            )
            await self.frame_handler.write_frame(self.writer, response)
        except Exception as e:
            logger.error(f"Failed to send error response: {e}")

    async def _process_command(self, command: EPPCommand) -> bytes:
        """
        Process an EPP command and return response.

        Args:
            command: Parsed EPP command

        Returns:
            XML response bytes
        """
        cl_trid = command.client_transaction_id

        # Handle hello (no auth required)
        if command.command_type == "hello":
            return self.response_builder.build_greeting()

        # Handle login (no prior auth required)
        if command.command_type == "login":
            return await self._handle_login(command)

        # All other commands require authentication
        if not self.authenticated:
            return self.response_builder.build_error(
                code=2002,
                message="Command use error: not logged in",
                cl_trid=cl_trid
            )

        # Handle logout
        if command.command_type == "logout":
            return await self._handle_logout(command)

        # Handle poll
        if command.command_type == "poll":
            return await self._handle_poll(command)

        # Object commands - dispatch to appropriate handler
        return await self._handle_object_command(command)

    async def _handle_login(self, command: EPPCommand) -> bytes:
        """Handle login command."""
        cl_trid = command.client_transaction_id
        data = command.data

        # Already logged in?
        if self.authenticated:
            return self.response_builder.build_error(
                code=2002,
                message="Command use error: already logged in",
                cl_trid=cl_trid
            )

        # Extract credentials
        client_id = data.get("clID")
        password = data.get("pw")

        if not client_id or not password:
            return self.response_builder.build_error(
                code=2003,
                message="Required parameter missing: clID and pw required",
                cl_trid=cl_trid
            )

        logger.info(f"Login attempt: {client_id} from {self.client_ip}")

        try:
            # Authenticate against database
            account_repo = get_account_repo()
            user = await account_repo.authenticate_user(client_id, password)

            if user is None:
                logger.warning(f"Authentication failed for {client_id} from {self.client_ip}")
                return self.response_builder.build_error(
                    code=2200,
                    message="Authentication error: invalid credentials",
                    cl_trid=cl_trid
                )

            # Check IP whitelist
            ip_allowed = await account_repo.check_ip_whitelist(user.USR_ACC_ID, self.client_ip)
            if not ip_allowed:
                logger.warning(f"IP {self.client_ip} not whitelisted for account {user.USR_ACC_ID}")
                return self.response_builder.build_error(
                    code=2200,
                    message="Authentication error: IP address not authorized",
                    cl_trid=cl_trid
                )

            # Authentication successful
            from datetime import datetime

            self.authenticated = True
            self.client_id = client_id
            self.account_id = user.USR_ACC_ID
            self.user_id = user.USR_ID

            # Update session info for command handlers
            if self.session:
                self.session.authenticated = True
                self.session.client_id = client_id
                self.session.account_id = user.USR_ACC_ID
                self.session.user_id = user.USR_ID
                self.session.username = user.USR_NAME
                self.session.login_time = datetime.utcnow()

            logger.info(f"Login successful: {client_id} (account {user.USR_ACC_ID}) from {self.client_ip}")

            return self.response_builder.build_response(
                code=1000,
                message="Command completed successfully",
                cl_trid=cl_trid
            )

        except Exception as e:
            logger.error(f"Login error for {client_id}: {e}")
            return self.response_builder.build_error(
                code=2400,
                message="Command failed: internal server error",
                cl_trid=cl_trid
            )

    async def _handle_logout(self, command: EPPCommand) -> bytes:
        """Handle logout command."""
        cl_trid = command.client_transaction_id

        # Clear session state
        self.authenticated = False
        self.client_id = None
        self.account_id = None

        # Update session info
        if self.session:
            self.session.authenticated = False

        return self.response_builder.build_response(
            code=1500,
            message="Command completed successfully; ending session",
            cl_trid=cl_trid
        )

    async def _handle_poll(self, command: EPPCommand) -> bytes:
        """Handle poll command."""
        cl_trid = command.client_transaction_id
        op = command.data.get("op", "req")

        if op == "req":
            # TODO: Check for pending messages
            return self.response_builder.build_response(
                code=1300,
                message="Command completed successfully; no messages",
                cl_trid=cl_trid
            )
        elif op == "ack":
            msg_id = command.data.get("msgID")
            if not msg_id:
                return self.response_builder.build_error(
                    code=2003,
                    message="Required parameter missing: msgID",
                    cl_trid=cl_trid
                )
            # TODO: Acknowledge message
            return self.response_builder.build_response(
                code=1000,
                message="Command completed successfully",
                cl_trid=cl_trid
            )
        else:
            return self.response_builder.build_error(
                code=2005,
                message=f"Parameter value syntax error: invalid op '{op}'",
                cl_trid=cl_trid
            )

    async def _handle_object_command(self, command: EPPCommand) -> bytes:
        """
        Handle object commands (domain, contact, host).

        Dispatches to the appropriate handler based on object type.
        """
        cl_trid = command.client_transaction_id
        object_type = command.object_type
        command_type = command.command_type

        # Get the appropriate handler factory
        if object_type == "domain":
            handler = get_domain_handler(command_type)
        elif object_type == "contact":
            handler = get_contact_handler(command_type)
        elif object_type == "host":
            handler = get_host_handler(command_type)
        else:
            return self.response_builder.build_error(
                code=2000,
                message=f"Unknown object type: {object_type}",
                cl_trid=cl_trid
            )

        if handler is None:
            return self.response_builder.build_error(
                code=2101,
                message=f"Unimplemented command: {object_type}:{command_type}",
                cl_trid=cl_trid
            )

        try:
            # Execute the handler with session info (includes logging)
            return await handler.execute(command, self.session)

        except Exception as e:
            logger.error(f"Error handling {object_type}:{command_type}: {e}", exc_info=True)
            return self.response_builder.build_error(
                code=2400,
                message="Command failed: internal server error",
                cl_trid=cl_trid
            )

    async def _cleanup(self) -> None:
        """Clean up connection resources."""
        try:
            # TODO: End session/connection in database

            self.writer.close()
            await self.writer.wait_closed()
            logger.info(f"Connection closed: {self.client_ip}:{self.client_port}")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


class EPPServer:
    """
    Main EPP server class.

    Manages:
    - Configuration loading
    - TLS setup
    - Database connection pool
    - Client connection handling
    - Graceful shutdown
    """

    def __init__(self, config_path: str = "config/epp.yaml"):
        """Initialize EPP server."""
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.tls_handler: Optional[TLSHandler] = None
        self.frame_handler: Optional[FrameHandler] = None
        self.xml_processor: Optional[XMLProcessor] = None
        self.response_builder: Optional[ResponseBuilder] = None
        self.server: Optional[asyncio.Server] = None
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._active_connections: int = 0

    def load_config(self) -> None:
        """Load configuration from YAML file."""
        config_file = Path(self.config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(config_file, "r") as f:
            self.config = yaml.safe_load(f)

        logger.info(f"Loaded configuration from {self.config_path}")

    def setup_logging(self) -> None:
        """Configure logging from YAML file."""
        logging_config = Path("config/logging.yaml")
        if logging_config.exists():
            with open(logging_config, "r") as f:
                log_config = yaml.safe_load(f)
                # Ensure log directory exists
                log_dir = Path("/var/log/epp-server")
                if not log_dir.exists():
                    try:
                        log_dir.mkdir(parents=True, exist_ok=True)
                    except PermissionError:
                        # Fall back to current directory
                        for handler in log_config.get("handlers", {}).values():
                            if "filename" in handler:
                                handler["filename"] = handler["filename"].replace(
                                    "/var/log/epp-server/",
                                    "./logs/"
                                )
                        Path("./logs").mkdir(exist_ok=True)

                logging.config.dictConfig(log_config)
        else:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

    async def initialize(self) -> None:
        """Initialize all server components."""
        # Load config
        self.load_config()

        # Setup TLS
        tls_config = self.config.get("tls", {})
        self.tls_handler = TLSHandler(
            cert_file=tls_config.get("cert_file", "/opt/epp-server/config/tls/server.crt"),
            key_file=tls_config.get("key_file", "/opt/epp-server/config/tls/server.key"),
            ca_file=tls_config.get("ca_file", "/opt/epp-server/config/tls/ca-bundle.crt"),
            min_version=tls_config.get("min_version", "TLSv1.2"),
            verify_client=tls_config.get("verify_client", True)
        )

        # Setup frame handler
        server_config = self.config.get("server", {})
        self.frame_handler = FrameHandler(
            read_timeout=server_config.get("read_timeout", 60)
        )

        # Setup XML processor
        self.xml_processor = XMLProcessor()

        # Setup response builder
        epp_config = self.config.get("epp", {})
        self.response_builder = initialize_response_builder(epp_config)

        # Initialize database pool
        oracle_config = self.config.get("oracle", {})
        try:
            await initialize_pool(oracle_config)
            logger.info("Database pool initialized")
        except Exception as e:
            logger.warning(f"Database pool initialization failed: {e}")
            logger.warning("Server will start but database operations will fail")

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection."""
        # Check connection limit
        max_connections = self.config.get("server", {}).get("max_connections", 100)
        if self._active_connections >= max_connections:
            logger.warning("Connection limit reached, rejecting client")
            writer.close()
            await writer.wait_closed()
            return

        self._active_connections += 1

        try:
            handler = EPPClientHandler(
                reader=reader,
                writer=writer,
                frame_handler=self.frame_handler,
                xml_processor=self.xml_processor,
                response_builder=self.response_builder,
                config=self.config
            )
            await handler.handle()

        finally:
            self._active_connections -= 1

    async def start(self) -> None:
        """Start the EPP server."""
        await self.initialize()

        server_config = self.config.get("server", {})
        host = server_config.get("host", "0.0.0.0")
        port = server_config.get("port", 700)

        # Create SSL context
        try:
            ssl_context = self.tls_handler.create_ssl_context()
        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            logger.info("Starting server without TLS (development mode)")
            ssl_context = None

        # Start server
        self.server = await asyncio.start_server(
            self.handle_client,
            host=host,
            port=port,
            ssl=ssl_context
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"EPP Server listening on {addrs}")

        # Wait for shutdown signal
        await self._shutdown_event.wait()

    async def stop(self) -> None:
        """Stop the EPP server gracefully."""
        logger.info("Shutting down EPP server...")

        # Signal shutdown
        self._shutdown_event.set()

        # Stop accepting new connections
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        # Wait for active connections to complete (with timeout)
        timeout = 30
        while self._active_connections > 0 and timeout > 0:
            logger.info(f"Waiting for {self._active_connections} connections to close...")
            await asyncio.sleep(1)
            timeout -= 1

        # Close database pool
        await close_pool()

        logger.info("EPP Server stopped")

    def signal_handler(self, sig: signal.Signals) -> None:
        """Handle shutdown signals."""
        logger.info(f"Received signal {sig.name}")
        self._shutdown_event.set()


async def main() -> None:
    """Main entry point."""
    # Determine config path
    config_path = os.environ.get("EPP_CONFIG", "config/epp.yaml")

    # Create server
    server = EPPServer(config_path)

    # Setup logging
    server.setup_logging()

    # Setup signal handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: server.signal_handler(s))

    try:
        await server.start()
    except KeyboardInterrupt:
        pass
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
