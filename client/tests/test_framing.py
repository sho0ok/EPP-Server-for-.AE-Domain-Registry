"""
Tests for EPP framing module.
"""

import pytest
from epp_client.framing import (
    encode_frame,
    decode_frame_header,
    FrameReader,
    FrameWriter,
    MAX_FRAME_SIZE,
    MIN_FRAME_SIZE,
)
from epp_client.exceptions import EPPFrameError


class TestEncodeFrame:
    """Tests for frame encoding."""

    def test_encode_empty(self):
        """Encode empty payload."""
        result = encode_frame(b"")
        assert result == b"\x00\x00\x00\x04"  # Length = 4 (header only)

    def test_encode_simple(self):
        """Encode simple payload."""
        data = b"test"
        result = encode_frame(data)
        # Length = 4 (header) + 4 (data) = 8
        assert result == b"\x00\x00\x00\x08test"

    def test_encode_xml(self):
        """Encode XML payload."""
        data = b'<?xml version="1.0"?><epp/>'
        result = encode_frame(data)
        # Check header
        length = int.from_bytes(result[:4], "big")
        assert length == len(data) + 4
        # Check payload
        assert result[4:] == data

    def test_encode_too_large(self):
        """Reject payload exceeding max size."""
        data = b"x" * (MAX_FRAME_SIZE + 1)
        with pytest.raises(EPPFrameError) as exc:
            encode_frame(data)
        assert "too large" in str(exc.value).lower()


class TestDecodeFrameHeader:
    """Tests for frame header decoding."""

    def test_decode_minimum(self):
        """Decode minimum valid header."""
        header = b"\x00\x00\x00\x04"  # Length = 4
        result = decode_frame_header(header)
        assert result == 4

    def test_decode_normal(self):
        """Decode normal header."""
        header = b"\x00\x00\x01\x00"  # Length = 256
        result = decode_frame_header(header)
        assert result == 256

    def test_decode_large(self):
        """Decode large valid header."""
        # Just under max
        header = b"\x00\x98\x96\x80"  # Length = 10,000,000
        result = decode_frame_header(header)
        assert result == 10_000_000

    def test_decode_invalid_length(self):
        """Reject invalid header length."""
        with pytest.raises(EPPFrameError):
            decode_frame_header(b"\x00\x00\x00")  # Only 3 bytes

    def test_decode_too_small(self):
        """Reject length smaller than minimum."""
        header = b"\x00\x00\x00\x03"  # Length = 3
        with pytest.raises(EPPFrameError) as exc:
            decode_frame_header(header)
        assert "too small" in str(exc.value).lower()

    def test_decode_too_large(self):
        """Reject length exceeding max."""
        header = b"\x01\x00\x00\x00"  # Length = 16,777,216
        with pytest.raises(EPPFrameError) as exc:
            decode_frame_header(header)
        assert "too large" in str(exc.value).lower()


class TestFrameReaderWriter:
    """Tests for FrameReader and FrameWriter."""

    def test_reader_single_frame(self):
        """Read single complete frame."""
        data = b"\x00\x00\x00\x08test"

        chunks = [data]
        chunk_iter = iter(chunks)

        def read_func(n):
            try:
                return next(chunk_iter)
            except StopIteration:
                return b""

        reader = FrameReader(read_func)
        result = reader.read_frame()
        assert result == b"test"

    def test_reader_chunked(self):
        """Read frame received in chunks."""
        # Frame: length=8, payload="test"
        chunks = [
            b"\x00\x00",  # First part of header
            b"\x00\x08te",  # Rest of header + start of payload
            b"st",  # Rest of payload
        ]
        chunk_iter = iter(chunks)

        def read_func(n):
            try:
                return next(chunk_iter)
            except StopIteration:
                return b""

        reader = FrameReader(read_func)
        result = reader.read_frame()
        assert result == b"test"

    def test_writer_simple(self):
        """Write simple frame."""
        written_data = []

        def write_func(data):
            written_data.append(data)
            return len(data)

        writer = FrameWriter(write_func)
        writer.write_frame(b"test")

        # Should write: header + payload
        frame = b"".join(written_data)
        assert frame == b"\x00\x00\x00\x08test"

    def test_roundtrip(self):
        """Encode and decode roundtrip."""
        original = b'<?xml version="1.0"?><epp xmlns="urn:ietf:params:xml:ns:epp-1.0"/>'

        # Encode
        frame = encode_frame(original)

        # Decode header
        length = decode_frame_header(frame[:4])
        assert length == len(original) + 4

        # Extract payload
        payload = frame[4:]
        assert payload == original
