"""
EPP Frame Handler

Handles EPP protocol framing with 4-byte length prefix as per RFC 5734.
All EPP messages are prefixed with a 4-byte big-endian integer indicating
the total length including the 4-byte header.
"""

import asyncio
import struct
import logging
from typing import Optional

logger = logging.getLogger("epp.frame")

# EPP frame constants
HEADER_SIZE = 4  # 4-byte length prefix
MAX_FRAME_SIZE = 10 * 1024 * 1024  # 10MB max frame size
MIN_FRAME_SIZE = HEADER_SIZE + 1  # Minimum valid frame


class FrameError(Exception):
    """Base exception for frame handling errors"""
    pass


class FrameReadError(FrameError):
    """Error reading frame from connection"""
    pass


class FrameWriteError(FrameError):
    """Error writing frame to connection"""
    pass


class FrameSizeError(FrameError):
    """Frame size exceeds limits"""
    pass


class FrameHandler:
    """
    Handles EPP frame encoding and decoding.

    EPP uses a simple framing protocol:
    - 4-byte big-endian integer: total message length (including this header)
    - Variable bytes: XML message

    Example:
        If XML message is 100 bytes, the frame is:
        [00 00 00 68] (104 in big-endian) + [100 bytes of XML]
    """

    def __init__(
        self,
        read_timeout: float = 60.0,
        max_frame_size: int = MAX_FRAME_SIZE
    ):
        """
        Initialize frame handler.

        Args:
            read_timeout: Timeout in seconds for read operations
            max_frame_size: Maximum allowed frame size in bytes
        """
        self.read_timeout = read_timeout
        self.max_frame_size = max_frame_size

    async def read_frame(
        self,
        reader: asyncio.StreamReader,
        timeout: Optional[float] = None
    ) -> bytes:
        """
        Read a complete EPP frame from the stream.

        Args:
            reader: asyncio StreamReader
            timeout: Optional timeout override

        Returns:
            XML data (without length header)

        Raises:
            FrameReadError: If read fails or connection closed
            FrameSizeError: If frame exceeds max size
            asyncio.TimeoutError: If read times out
        """
        read_timeout = timeout or self.read_timeout

        try:
            # Read 4-byte length header
            header = await asyncio.wait_for(
                reader.readexactly(HEADER_SIZE),
                timeout=read_timeout
            )

            # Unpack big-endian unsigned int
            total_length = struct.unpack("!I", header)[0]

            logger.debug(f"Frame header indicates {total_length} bytes total")

            # Validate frame size
            if total_length < MIN_FRAME_SIZE:
                raise FrameSizeError(
                    f"Frame too small: {total_length} bytes (minimum {MIN_FRAME_SIZE})"
                )

            if total_length > self.max_frame_size:
                raise FrameSizeError(
                    f"Frame too large: {total_length} bytes (maximum {self.max_frame_size})"
                )

            # Calculate data length (total minus header)
            data_length = total_length - HEADER_SIZE

            # Read XML data
            data = await asyncio.wait_for(
                reader.readexactly(data_length),
                timeout=read_timeout
            )

            logger.debug(f"Read {len(data)} bytes of XML data")

            return data

        except asyncio.IncompleteReadError as e:
            if e.partial:
                logger.warning(f"Connection closed with {len(e.partial)} bytes pending")
            else:
                logger.debug("Connection closed cleanly")
            raise FrameReadError("Connection closed during read") from e

        except asyncio.TimeoutError:
            logger.warning(f"Read timeout after {read_timeout} seconds")
            raise

        except struct.error as e:
            raise FrameReadError(f"Invalid frame header: {e}") from e

    async def write_frame(
        self,
        writer: asyncio.StreamWriter,
        data: bytes
    ) -> None:
        """
        Write an EPP frame to the stream.

        Args:
            writer: asyncio StreamWriter
            data: XML data to send

        Raises:
            FrameWriteError: If write fails
            FrameSizeError: If data exceeds max size
        """
        # Validate size
        total_length = HEADER_SIZE + len(data)
        if total_length > self.max_frame_size:
            raise FrameSizeError(
                f"Frame too large: {total_length} bytes (maximum {self.max_frame_size})"
            )

        try:
            # Pack length as big-endian unsigned int
            header = struct.pack("!I", total_length)

            # Write header and data
            writer.write(header + data)
            await writer.drain()

            logger.debug(f"Wrote frame: {total_length} bytes total")

        except ConnectionError as e:
            raise FrameWriteError(f"Connection error during write: {e}") from e

        except Exception as e:
            raise FrameWriteError(f"Write failed: {e}") from e

    async def read_frame_with_retry(
        self,
        reader: asyncio.StreamReader,
        max_retries: int = 3,
        retry_delay: float = 0.1
    ) -> Optional[bytes]:
        """
        Read frame with retry on transient errors.

        Args:
            reader: asyncio StreamReader
            max_retries: Maximum retry attempts
            retry_delay: Delay between retries in seconds

        Returns:
            XML data or None if all retries fail
        """
        last_error = None

        for attempt in range(max_retries):
            try:
                return await self.read_frame(reader)
            except asyncio.TimeoutError as e:
                last_error = e
                if attempt < max_retries - 1:
                    logger.debug(f"Read timeout, retry {attempt + 1}/{max_retries}")
                    await asyncio.sleep(retry_delay)
            except FrameReadError as e:
                # Connection errors are not retryable
                raise

        logger.warning(f"All {max_retries} read attempts failed")
        if last_error:
            raise last_error
        return None


def encode_frame(data: bytes) -> bytes:
    """
    Encode data as EPP frame (synchronous utility function).

    Args:
        data: XML data to encode

    Returns:
        Complete frame with length header
    """
    total_length = HEADER_SIZE + len(data)
    header = struct.pack("!I", total_length)
    return header + data


def decode_frame_header(header: bytes) -> int:
    """
    Decode EPP frame header (synchronous utility function).

    Args:
        header: 4-byte header

    Returns:
        Total frame length including header

    Raises:
        ValueError: If header is invalid
    """
    if len(header) != HEADER_SIZE:
        raise ValueError(f"Header must be {HEADER_SIZE} bytes, got {len(header)}")
    return struct.unpack("!I", header)[0]
