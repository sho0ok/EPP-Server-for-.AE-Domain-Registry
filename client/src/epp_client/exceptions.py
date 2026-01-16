"""
EPP Client Exceptions

Custom exception hierarchy for EPP operations.
"""


class EPPError(Exception):
    """Base EPP exception."""

    def __init__(self, message: str, code: int = None):
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self):
        if self.code:
            return f"[{self.code}] {self.message}"
        return self.message


class EPPConnectionError(EPPError):
    """Connection to EPP server failed."""

    def __init__(self, message: str = "Connection failed"):
        super().__init__(message)


class EPPFrameError(EPPError):
    """EPP frame encoding/decoding error."""

    def __init__(self, message: str = "Frame error"):
        super().__init__(message)


class EPPXMLError(EPPError):
    """XML parsing or building error."""

    def __init__(self, message: str = "XML error"):
        super().__init__(message)


class EPPAuthenticationError(EPPError):
    """Authentication failed (2200)."""

    def __init__(self, message: str = "Authentication error"):
        super().__init__(message, code=2200)


class EPPAuthorizationError(EPPError):
    """Not authorized for operation (2201)."""

    def __init__(self, message: str = "Authorization error"):
        super().__init__(message, code=2201)


class EPPCommandError(EPPError):
    """Command execution failed."""

    def __init__(self, message: str, code: int, reason: str = None):
        super().__init__(message, code)
        self.reason = reason

    def __str__(self):
        base = f"[{self.code}] {self.message}"
        if self.reason:
            base += f" - {self.reason}"
        return base


class EPPObjectNotFound(EPPCommandError):
    """Object does not exist (2303)."""

    def __init__(self, object_type: str, identifier: str):
        super().__init__(
            message="Object does not exist",
            code=2303,
            reason=f"{object_type} '{identifier}' not found"
        )


class EPPObjectExists(EPPCommandError):
    """Object already exists (2302)."""

    def __init__(self, object_type: str, identifier: str):
        super().__init__(
            message="Object exists",
            code=2302,
            reason=f"{object_type} '{identifier}' already exists"
        )


class EPPParameterError(EPPCommandError):
    """Invalid parameter (2005)."""

    def __init__(self, message: str = "Parameter value error", value: str = None):
        super().__init__(
            message=message,
            code=2005,
            reason=f"Invalid value: {value}" if value else None
        )


class EPPSessionError(EPPError):
    """Session-related error."""

    def __init__(self, message: str = "Session error"):
        super().__init__(message)


class EPPNotLoggedIn(EPPSessionError):
    """Not logged in (2002)."""

    def __init__(self):
        super().__init__("Command use error: not logged in")
        self.code = 2002


class EPPAlreadyLoggedIn(EPPSessionError):
    """Already logged in (2002)."""

    def __init__(self):
        super().__init__("Command use error: already logged in")
        self.code = 2002


# EPP Response Code Mapping
EPP_ERRORS = {
    2000: EPPError,
    2001: EPPError,
    2002: EPPSessionError,
    2003: EPPParameterError,
    2004: EPPParameterError,
    2005: EPPParameterError,
    2100: EPPError,
    2101: EPPError,
    2102: EPPError,
    2103: EPPError,
    2104: EPPError,
    2105: EPPError,
    2200: EPPAuthenticationError,
    2201: EPPAuthorizationError,
    2202: EPPError,
    2300: EPPError,
    2301: EPPError,
    2302: EPPObjectExists,
    2303: EPPObjectNotFound,
    2304: EPPError,
    2305: EPPError,
    2306: EPPParameterError,
    2307: EPPError,
    2308: EPPError,
    2400: EPPError,
    2500: EPPError,
    2501: EPPError,
    2502: EPPError,
}


def raise_for_code(code: int, message: str, reason: str = None):
    """Raise appropriate exception for EPP response code."""
    if code < 2000:
        return  # Success codes

    exc_class = EPP_ERRORS.get(code, EPPCommandError)

    if exc_class in (EPPObjectNotFound, EPPObjectExists):
        # These need special handling
        raise EPPCommandError(message, code, reason)

    if exc_class == EPPCommandError:
        raise EPPCommandError(message, code, reason)

    raise exc_class(message)
