import zlib
import lzma
import struct
from enum import IntEnum


class Compression(IntEnum):
    ZLIB = 0x01
    LZMA = 0x02


ZLIB_LEVEL: int = 6


def compress(data: bytes, method: Compression = Compression.ZLIB) -> bytes:
    if method == Compression.ZLIB:
        compressed = zlib.compress(data, level=ZLIB_LEVEL)
    elif method == Compression.LZMA:
        compressed = lzma.compress(data)
    else:
        raise ValueError(f"Unknown compression algorithm: {method}")

    return struct.pack("B", int(method)) + compressed


def decompress(data: bytes) -> bytes:
    if len(data) < 1:
        raise ValueError("Data block is empty.")

    method_byte = struct.unpack("B", data[:1])[0]
    compressed_payload = data[1:]

    try:
        method = Compression(method_byte)
    except ValueError:
        raise ValueError(f"Unknown compression algorithm identifier: {method_byte:#x}")

    try:
        if method == Compression.ZLIB:
            return zlib.decompress(compressed_payload)
        elif method == Compression.LZMA:
            return lzma.decompress(compressed_payload)
    except Exception as exc:
        raise ValueError(f"Data decompression error: {exc}") from exc
