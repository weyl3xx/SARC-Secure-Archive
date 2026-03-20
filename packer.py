import io
import os
import random
import secrets
from pathlib import Path
from typing import List, Tuple

from archive_format import (
    ArchiveHeader,
    FileEntry,
    FileTable,
    MAGIC,
    FORMAT_VERSION,
    HEADER_SIZE,
)
from crypto_utils import derive_key, encrypt, sha256_hash, sha256_hex, generate_salt
from compressor import compress, Compression
from utils import collect_files, random_padding, format_size

DEFAULT_KDF_ITERATIONS: int = 200_000


def pack_archive(
    source_dir: Path,
    archive_path: Path,
    password: str,
    kdf_iterations: int = DEFAULT_KDF_ITERATIONS,
    compression: Compression = Compression.ZLIB,
) -> None:
    print(f"[*] Source:      {source_dir}")
    print(f"[*] Archive:     {archive_path}")
    print(f"[*] Iterations:  {kdf_iterations:,}")

    files = collect_files(source_dir)
    if not files:
        raise ValueError(f"Directory is empty or contains no files: {source_dir}")

    print(f"[*] Found files: {len(files)}")

    salt = generate_salt()
    print("[*] Generating encryption key...")
    key = derive_key(password, salt, kdf_iterations)

    prepared: List[Tuple[FileEntry, bytes]] = []

    for abs_path, rel_path in files:
        raw_data = abs_path.read_bytes()
        original_size = len(raw_data)
        file_hash = sha256_hex(raw_data)

        compressed_data = compress(raw_data, method=compression)
        encrypted_data = encrypt(compressed_data, key)

        entry = FileEntry(
            name=abs_path.name,
            rel_path=rel_path,
            data_offset=0,
            compressed_size=len(encrypted_data),
            original_size=original_size,
            sha256=file_hash,
        )
        prepared.append((entry, encrypted_data))

        print(
            f"  ✓ {rel_path}  "
            f"{format_size(original_size)} → {format_size(len(encrypted_data))}"
        )

    random.shuffle(prepared)

    data_buffer = io.BytesIO()
    relative_offsets: List[int] = []

    for entry, enc_data in prepared:
        if data_buffer.tell() > 0:
            pad = random_padding(16, 128)
            data_buffer.write(pad)

        relative_offsets.append(data_buffer.tell())
        data_buffer.write(enc_data)

    raw_data_bytes = data_buffer.getvalue()

    file_entries_draft = []
    for i, (entry, _) in enumerate(prepared):
        draft = FileEntry(
            name=entry.name,
            rel_path=entry.rel_path,
            data_offset=relative_offsets[i],
            compressed_size=entry.compressed_size,
            original_size=entry.original_size,
            sha256=entry.sha256,
        )
        file_entries_draft.append(draft)

    table_draft = FileTable(entries=file_entries_draft)
    enc_table_draft = encrypt(table_draft.serialize(), key)
    table_size = len(enc_table_draft)

    data_base_offset = HEADER_SIZE + table_size

    file_entries_final = []
    for i, entry in enumerate(file_entries_draft):
        final_entry = FileEntry(
            name=entry.name,
            rel_path=entry.rel_path,
            data_offset=data_base_offset + relative_offsets[i],
            compressed_size=entry.compressed_size,
            original_size=entry.original_size,
            sha256=entry.sha256,
        )
        file_entries_final.append(final_entry)

    table_final = FileTable(entries=file_entries_final)
    enc_table_final = encrypt(table_final.serialize(), key)

    archive_path.parent.mkdir(parents=True, exist_ok=True)

    header = ArchiveHeader(
        magic=MAGIC,
        version=FORMAT_VERSION,
        salt=salt,
        kdf_iterations=kdf_iterations,
        file_table_offset=HEADER_SIZE,
        file_table_size=table_size,
    )

    body = header.pack() + enc_table_final + raw_data_bytes

    archive_hash = sha256_hash(body)

    with archive_path.open("wb") as f:
        f.write(body)
        f.write(archive_hash)

    total_size = archive_path.stat().st_size
    print(f"\n[✓] Archive created: {archive_path}  ({format_size(total_size)})")
