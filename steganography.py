import struct
import secrets
from pathlib import Path
from typing import Tuple

from PIL import Image

from crypto_utils import sha256_hash


STEG_MAGIC: bytes = b"STEG"
STEG_VERSION: int = 0x01

PAYLOAD_HEADER_SIZE: int = 48

PAYLOAD_HEADER_STRUCT: str = ">4sBBBBQ32s"
assert struct.calcsize(PAYLOAD_HEADER_STRUCT) == PAYLOAD_HEADER_SIZE


def calculate_capacity(image: Image.Image, channels: int, bits: int) -> int:
    width, height = image.size
    total_bits = width * height * channels * bits
    return total_bits // 8


def check_capacity(image: Image.Image, data_size: int, channels: int, bits: int) -> None:
    capacity = calculate_capacity(image, channels, bits)
    needed = data_size + PAYLOAD_HEADER_SIZE

    if needed > capacity:
        raise ValueError(
            f"Image too small for embedding.\n"
            f"  Needed:    {needed:,} bytes ({needed / 1024:.1f} KB)\n"
            f"  Capacity:  {capacity:,} bytes ({capacity / 1024:.1f} KB)\n"
            f"  Pixels:    {image.width} × {image.height} = {image.width * image.height:,}\n"
            f"  Settings:  {channels} channels, {bits} bits/channel\n"
            f"  Tip:       use larger image or increase --bits"
        )


def _bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def _set_lsb(value: int, bit: int, bit_pos: int, bits_per_channel: int) -> int:
    mask = ~(1 << bit_pos) & 0xFF
    return (value & mask) | (bit << bit_pos)


def _get_lsb(value: int, bit_pos: int) -> int:
    return (value >> bit_pos) & 1


def embed(
    image: Image.Image,
    data: bytes,
    channels: int = 3,
    bits: int = 1,
) -> Image.Image:
    img = image.convert("RGBA")
    img_load = img.load()
    pixels = [img_load[x, y] for y in range(img.height) for x in range(img.width)]

    check_capacity(img, len(data) - PAYLOAD_HEADER_SIZE, channels, bits)

    payload_bits = _bytes_to_bits(data)
    bit_index = 0
    total_bits = len(payload_bits)

    new_pixels = []
    for pixel in pixels:
        if bit_index >= total_bits:
            new_pixels.append(pixel)
            continue

        px = list(pixel)

        for ch in range(min(channels, len(px))):
            for bit_pos in range(bits):
                if bit_index < total_bits:
                    px[ch] = _set_lsb(px[ch], payload_bits[bit_index], bit_pos, bits)
                    bit_index += 1

        new_pixels.append(tuple(px))

    result = Image.new("RGBA", img.size)
    result_load = result.load()
    width = img.width
    for idx, px in enumerate(new_pixels):
        result_load[idx % width, idx // width] = px
    return result


def extract(image: Image.Image, channels: int, bits: int) -> bytes:
    img = image.convert("RGBA")
    pixels = list(img.getdata())

    header_bits_needed = PAYLOAD_HEADER_SIZE * 8

    header_bits = _read_bits_from_pixels(pixels, channels, bits, header_bits_needed)
    header_bytes = _bits_to_bytes(header_bits)

    magic, version, ch_stored, bits_stored, _res, data_size, stored_hash = struct.unpack(
        PAYLOAD_HEADER_STRUCT, header_bytes[:PAYLOAD_HEADER_SIZE]
    )

    if magic != STEG_MAGIC:
        raise ValueError(
            f"Steganography signature not found: expected {STEG_MAGIC!r}, "
            f"got {magic!r}.\n"
            f"Image might not contain hidden data, "
            f"or wrong parameters specified (--channels / --bits)."
        )

    if version != STEG_VERSION:
        raise ValueError(f"Unsupported stego format version: {version}")

    if ch_stored != channels or bits_stored != bits:
        raise ValueError(
            f"Parameters don't match those used during embedding.\n"
            f"  During embedding: channels={ch_stored}, bits={bits_stored}\n"
            f"  Currently specified: channels={channels}, bits={bits}\n"
            f"  Hint: use same --channels and --bits as during hide."
        )

    total_bits_needed = (PAYLOAD_HEADER_SIZE + data_size) * 8
    all_bits = _read_bits_from_pixels(pixels, channels, bits, total_bits_needed)
    all_bytes = _bits_to_bytes(all_bits)

    payload = all_bytes[PAYLOAD_HEADER_SIZE: PAYLOAD_HEADER_SIZE + data_size]

    actual_hash = sha256_hash(payload)
    if actual_hash != stored_hash:
        raise ValueError(
            "SHA-256 hash of extracted data doesn't match stored hash.\n"
            "Data is corrupted or image was modified after embedding."
        )

    return payload


def _read_bits_from_pixels(
    pixels: list,
    channels: int,
    bits: int,
    count: int,
) -> list[int]:
    result = []
    for pixel in pixels:
        if len(result) >= count:
            break
        for ch in range(min(channels, len(pixel))):
            for bit_pos in range(bits):
                if len(result) < count:
                    result.append(_get_lsb(pixel[ch], bit_pos))
    return result


def build_payload(data: bytes, channels: int, bits: int) -> bytes:
    data_hash = sha256_hash(data)
    header = struct.pack(
        PAYLOAD_HEADER_STRUCT,
        STEG_MAGIC,
        STEG_VERSION,
        channels,
        bits,
        0x00,
        len(data),
        data_hash,
    )
    return header + data


def parse_payload(payload_with_header: bytes) -> bytes:
    return payload_with_header[PAYLOAD_HEADER_SIZE:]


def hide_file_in_image(
    archive_path: Path,
    cover_image_path: Path,
    output_image_path: Path,
    channels: int = 3,
    bits: int = 1,
) -> None:
    if not archive_path.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")
    if not cover_image_path.exists():
        raise FileNotFoundError(f"Image not found: {cover_image_path}")

    _validate_params(channels, bits)

    archive_data = archive_path.read_bytes()
    archive_size = len(archive_data)

    print(f"[*] Archive:          {archive_path}  ({archive_size / 1024:.1f} KB)")
    print(f"[*] Cover image:      {cover_image_path}")
    print(f"[*] Channels:         {channels}  (of 4 RGBA)")
    print(f"[*] Bits per channel: {bits}")

    try:
        cover_image = Image.open(cover_image_path)
    except Exception as exc:
        raise ValueError(f"Failed to open image: {exc}")

    w, h = cover_image.size
    capacity = calculate_capacity(cover_image.convert("RGBA"), channels, bits)
    payload_size = archive_size + PAYLOAD_HEADER_SIZE

    print(f"[*] Canvas size:      {w} × {h} pixels")
    print(f"[*] Capacity:         {capacity / 1024:.1f} KB")
    print(f"[*] Needed:           {payload_size / 1024:.1f} KB  ", end="")
    print(f"({payload_size / capacity * 100:.1f}% of capacity)")

    payload = build_payload(archive_data, channels, bits)
    result_image = embed(cover_image, payload, channels=channels, bits=bits)

    output_path = output_image_path.with_suffix(".png")
    result_image.save(output_path, format="PNG", optimize=False)

    print(f"\n[✓] Archive hidden in image: {output_path}")
    print(f"    Visual change: minimal (LSB {bits}-bit)")


def extract_file_from_image(
    stego_image_path: Path,
    output_archive_path: Path,
    channels: int = 3,
    bits: int = 1,
) -> None:
    if not stego_image_path.exists():
        raise FileNotFoundError(f"Image not found: {stego_image_path}")

    _validate_params(channels, bits)

    print(f"[*] Stego image:      {stego_image_path}")
    print(f"[*] Channels:         {channels}")
    print(f"[*] Bits per channel: {bits}")

    try:
        stego_image = Image.open(stego_image_path)
    except Exception as exc:
        raise ValueError(f"Failed to open image: {exc}")

    print("[*] Extracting data from LSB pixels...")
    archive_data = extract(stego_image, channels=channels, bits=bits)

    output_archive_path.parent.mkdir(parents=True, exist_ok=True)
    output_archive_path.write_bytes(archive_data)

    print(f"[✓] Archive extracted: {output_archive_path}  ({len(archive_data) / 1024:.1f} KB)")
    print(f"[✓] Integrity verified (SHA-256 matches).")


def image_info(image_path: Path) -> None:
    if not image_path.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")

    img = Image.open(image_path).convert("RGBA")
    w, h = img.size
    px = w * h

    print(f"\n[*] Image: {image_path}")
    print(f"    Size: {w} × {h} = {px:,} pixels\n")
    print(f"    {'Channels':>8} {'Bits':>4} {'Capacity':>14} {'Usable Payload':>18}")
    print(f"    {'-'*8} {'-'*4} {'-'*14} {'-'*18}")

    for ch in (1, 2, 3, 4):
        for b in (1, 2, 4):
            cap = calculate_capacity(img, ch, b)
            usable = max(0, cap - PAYLOAD_HEADER_SIZE)
            bar = "█" * min(int(usable / 1024 / 10), 20)
            print(f"    {ch:>8} {b:>4} {cap / 1024:>11.1f} KB {usable / 1024:>14.1f} KB  {bar}")


def _validate_params(channels: int, bits: int) -> None:
    if not 1 <= channels <= 4:
        raise ValueError(f"channels must be from 1 to 4, got: {channels}")
    if not 1 <= bits <= 4:
        raise ValueError(f"bits must be from 1 to 4, got: {bits}")
