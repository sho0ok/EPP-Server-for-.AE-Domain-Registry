"""
EPP Framing

Handles EPP frame encoding/decoding per RFC 5734.
Each EPP message is prefixed with a 4-byte length header (network byte order).
"""

import struct
from typing import Tuple

from epp_client.exceptions import EPPFrameError


# Maximum frame size (10MB - reasonable limit)
MAX_FRAME_SIZE = 10 * 1024 * 1024

# Minimum frame size (header only)
MIN_FRAME_SIZE = 4


def encode_frame(data: bytes) -> bytes:
    """
    Encode data with EPP 4-byte length prefix.

    The length includes the 4 header bytes themselves.

    Args:
        data: XML data to encode

    Returns:
        Framed data with length prefix

    Raises:
        EPPFrameError: If data is too large
    """
    total_length = len(data) + 4

    if total_length > MAX_FRAME_SIZE:
        raise EPPFrameError(f"Frame too large: {total_length} bytes (max {MAX_FRAME_SIZE})")

    # Pack length as 4-byte big-endian unsigned int
    header = struct.pack("!I", total_length)
    return header + data


def decode_frame_header(header: bytes) -> int:
    """
    Decode EPP frame header to get total length.

    Args:
        header: 4-byte header

    Returns:
        Total frame length (including header)

    Raises:
        EPPFrameError: If header is invalid
    """
    if len(header) != 4:
        raise EPPFrameError(f"Invalid header length: {len(header)} (expected 4)")

    length = struct.unpack("!I", header)[0]

    if length < MIN_FRAME_SIZE:
        raise EPPFrameError(f"Frame length too small: {length}")

    if length > MAX_FRAME_SIZE:
        raise EPPFrameError(f"Frame length too large: {length}")

    return length


def read_frame(read_func) -> bytes:
    """
    Read a complete EPP frame using provided read function.

    Args:
        read_func: Function that reads exactly n bytes (e.g., ssl_socket.recv)

    Returns:
        Frame payload (without header)

    Raises:
        EPPFrameError: If frame is invalid
    """
    # Read 4-byte header
    header = _read_exactly(read_func, 4)
    if not header:
        raise EPPFrameError("Connection closed while reading header")

    total_length = decode_frame_header(header)
    payload_length = total_length - 4

    if payload_length == 0:
        return b""

    # Read payload
    payload = _read_exactly(read_func, payload_length)
    if not payload or len(payload) != payload_length:
        raise EPPFrameError(f"Incomplete frame: got {len(payload) if payload else 0}, expected {payload_length}")

    return payload


def _read_exactly(read_func, length: int) -> bytes:
    """
    Read exactly the specified number of bytes.

    Args:
        read_func: Function to read data
        length: Number of bytes to read

    Returns:
        Bytes read
    """
    data = b""
    remaining = length

    while remaining > 0:
        chunk = read_func(remaining)
        if not chunk:
            break
        data += chunk
        remaining -= len(chunk)

    return data


class FrameReader:
    """
    Buffered frame reader for EPP connections.

    Handles partial reads and frame reassembly.
    """

    def __init__(self, read_func):
        """
        Initialize frame reader.

        Args:
            read_func: Function that reads up to n bytes
        """
        self.read_func = read_func
        self.buffer = b""

    def read_frame(self) -> bytes:
        """
        Read next complete frame.

        Returns:
            Frame payload

        Raises:
            EPPFrameError: If frame is invalid
        """
        # Ensure we have the header
        while len(self.buffer) < 4:
            chunk = self.read_func(4096)
            if not chunk:
                if self.buffer:
                    raise EPPFrameError("Connection closed with partial header")
                raise EPPFrameError("Connection closed")
            self.buffer += chunk

        # Parse header
        total_length = decode_frame_header(self.buffer[:4])
        payload_length = total_length - 4

        # Read until we have complete frame
        while len(self.buffer) < total_length:
            chunk = self.read_func(4096)
            if not chunk:
                raise EPPFrameError("Connection closed with partial frame")
            self.buffer += chunk

        # Extract frame
        payload = self.buffer[4:total_length]
        self.buffer = self.buffer[total_length:]

        return payload


class FrameWriter:
    """
    Frame writer for EPP connections.
    """

    def __init__(self, write_func):
        """
        Initialize frame writer.

        Args:
            write_func: Function that writes bytes
        """
        self.write_func = write_func

    def write_frame(self, data: bytes) -> int:
        """
        Write a complete frame.

        Args:
            data: Frame payload

        Returns:
            Number of bytes written (including header)

        Raises:
            EPPFrameError: If write fails
        """
        frame = encode_frame(data)
        total_written = 0

        while total_written < len(frame):
            written = self.write_func(frame[total_written:])
            if written is None or written <= 0:
                raise EPPFrameError("Failed to write frame")
            total_written += written

        return total_written
