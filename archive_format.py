import struct
import json
import dataclasses
from dataclasses import dataclass, field
from typing import List


MAGIC: bytes = b"SARC"
FORMAT_VERSION: int = 1

HEADER_SIZE: int = 80

HEADER_STRUCT: str = ">4sH32sIQQ22s"

assert struct.calcsize(HEADER_STRUCT) == HEADER_SIZE, (
    f"Header size {struct.calcsize(HEADER_STRUCT)} doesn't match {HEADER_SIZE}"
)


@dataclass
class ArchiveHeader:
    magic: bytes
    version: int
    salt: bytes
    kdf_iterations: int
    file_table_offset: int
    file_table_size: int

    def pack(self) -> bytes:
        return struct.pack(
            HEADER_STRUCT,
            self.magic,
            self.version,
            self.salt,
            self.kdf_iterations,
            self.file_table_offset,
            self.file_table_size,
            b"\x00" * 22,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "ArchiveHeader":
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"Data too short for header: {len(data)} < {HEADER_SIZE}"
            )

        magic, version, salt, kdf_iters, ft_offset, ft_size, _reserved = struct.unpack(
            HEADER_STRUCT, data[:HEADER_SIZE]
        )

        if magic != MAGIC:
            raise ValueError(
                f"Invalid archive signature: expected {MAGIC!r}, got {magic!r}"
            )
        if version != FORMAT_VERSION:
            raise ValueError(
                f"Unsupported format version: {version} (supported: {FORMAT_VERSION})"
            )

        return cls(
            magic=magic,
            version=version,
            salt=salt,
            kdf_iterations=kdf_iters,
            file_table_offset=ft_offset,
            file_table_size=ft_size,
        )


@dataclass
class FileEntry:
    name: str
    rel_path: str
    data_offset: int
    compressed_size: int
    original_size: int
    sha256: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FileEntry":
        return cls(**d)


@dataclass
class FileTable:
    entries: List[FileEntry] = field(default_factory=list)

    def serialize(self) -> bytes:
        data = [e.to_dict() for e in self.entries]
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @classmethod
    def deserialize(cls, data: bytes) -> "FileTable":
        raw = json.loads(data.decode("utf-8"))
        entries = [FileEntry.from_dict(item) for item in raw]
        return cls(entries=entries)
