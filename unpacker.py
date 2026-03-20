from pathlib import Path

from archive_format import (
    ArchiveHeader,
    FileTable,
    HEADER_SIZE,
)
from crypto_utils import derive_key, decrypt, sha256_hex, sha256_hash
from compressor import decompress
from utils import ensure_dir, safe_output_path, format_size


def unpack_archive(
    archive_path: Path,
    output_dir: Path,
    password: str,
) -> None:
    if not archive_path.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    print(f"[*] Archive:    {archive_path}")
    print(f"[*] Output:     {output_dir}")

    raw = archive_path.read_bytes()

    header = ArchiveHeader.unpack(raw)

    print(f"[*] Format:     SARC v{header.version}")
    print(f"[*] Iterations: {header.kdf_iterations:,}")

    _verify_archive_hash(raw)

    print("[*] Generating encryption key...")
    key = derive_key(password, header.salt, header.kdf_iterations)

    ft_start = header.file_table_offset
    ft_end = ft_start + header.file_table_size

    if ft_end > len(raw) - 32:
        raise ValueError("File table extends beyond archive bounds.")

    enc_table = raw[ft_start:ft_end]

    try:
        table_bytes = decrypt(enc_table, key)
    except ValueError as exc:
        raise ValueError(f"Failed to decrypt file table. Wrong password? ({exc})")

    file_table = FileTable.deserialize(table_bytes)
    print(f"[*] Files in archive: {len(file_table.entries)}")

    ensure_dir(output_dir)
    errors: list[str] = []

    for entry in file_table.entries:
        block_start = entry.data_offset
        block_end = block_start + entry.compressed_size

        if block_end > len(raw) - 32:
            errors.append(f"  ✗ {entry.rel_path}: offset beyond archive bounds")
            continue

        enc_block = raw[block_start:block_end]

        try:
            compressed_data = decrypt(enc_block, key)
        except ValueError as exc:
            errors.append(f"  ✗ {entry.rel_path}: decryption error — {exc}")
            continue

        try:
            file_data = decompress(compressed_data)
        except ValueError as exc:
            errors.append(f"  ✗ {entry.rel_path}: decompression error — {exc}")
            continue

        actual_hash = sha256_hex(file_data)
        if actual_hash != entry.sha256:
            errors.append(
                f"  ✗ {entry.rel_path}: SHA-256 mismatch\n"
                f"       expected: {entry.sha256}\n"
                f"       got:      {actual_hash}"
            )
            continue

        try:
            out_path = safe_output_path(output_dir, entry.rel_path)
        except ValueError as exc:
            errors.append(f"  ✗ {entry.rel_path}: unsafe path — {exc}")
            continue

        ensure_dir(out_path.parent)
        out_path.write_bytes(file_data)

        print(
            f"  ✓ {entry.rel_path}  "
            f"{format_size(entry.compressed_size)} → {format_size(len(file_data))}"
        )

    if errors:
        print(f"\n[!] Errors during unpacking ({len(errors)}):")
        for err in errors:
            print(err)
        raise ValueError(f"Unpacking completed with {len(errors)} errors.")

    print(f"\n[✓] Unpacking completed: {output_dir}")


def _verify_archive_hash(raw: bytes) -> None:
    if len(raw) < 32:
        raise ValueError("File too small for SARC archive.")

    body = raw[:-32]
    stored_hash = raw[-32:]
    computed_hash = sha256_hash(body)

    if computed_hash != stored_hash:
        raise ValueError(
            "Final archive hash doesn't match. "
            "File is corrupted or was modified after creation."
        )

    print("[✓] Archive integrity verified (SHA-256 matches).")
