import sys
import argparse
from pathlib import Path

from packer import pack_archive, DEFAULT_KDF_ITERATIONS
from unpacker import unpack_archive
from compressor import Compression
from utils import prompt_password
from password_utils import (
    generate_password,
    validate_password,
    print_password_policy,
    MIN_LENGTH,
    MAX_LENGTH,
)
from steganography import (
    hide_file_in_image,
    extract_file_from_image,
    image_info,
)


def cmd_pack(args: argparse.Namespace) -> int:
    source_dir = Path(args.source).resolve()
    archive_path = Path(args.archive).resolve()

    if archive_path.suffix.lower() not in (".sarc", ".secpack"):
        archive_path = archive_path.with_suffix(".sarc")

    compression = Compression.LZMA if args.lzma else Compression.ZLIB

    if args.password:
        print("[!] Warning: passing password via argument is insecure.")
        password = args.password
    else:
        try:
            password = prompt_password(confirm=True)
        except ValueError as exc:
            print(f"[✗] Error: {exc}", file=sys.stderr)
            return 1

    try:
        pack_archive(
            source_dir=source_dir,
            archive_path=archive_path,
            password=password,
            kdf_iterations=args.iterations,
            compression=compression,
        )
    except (FileNotFoundError, ValueError, IOError) as exc:
        print(f"\n[✗] Packing error: {exc}", file=sys.stderr)
        return 1

    return 0


def cmd_unpack(args: argparse.Namespace) -> int:
    archive_path = Path(args.archive).resolve()
    output_dir = Path(args.output).resolve()

    if args.password:
        print("[!] Warning: passing password via argument is insecure.")
        password = args.password
    else:
        try:
            password = prompt_password(confirm=False)
        except ValueError as exc:
            print(f"[✗] Error: {exc}", file=sys.stderr)
            return 1

    try:
        unpack_archive(
            archive_path=archive_path,
            output_dir=output_dir,
            password=password,
        )
    except (FileNotFoundError, ValueError, IOError) as exc:
        print(f"\n[✗] Unpacking error: {exc}", file=sys.stderr)
        return 1

    return 0


def cmd_genpass(args: argparse.Namespace) -> int:
    if args.validate:
        result = validate_password(args.validate)
        print(f"\n[*] Password analysis:")
        print(result)
        if result.is_valid:
            print("\n[✓] Password meets security requirements.")
        else:
            print("\n[✗] Password does NOT meet requirements.")
        return 0 if result.is_valid else 1

    count = args.count
    length = args.length

    print(f"\n[*] Generating {count} passwords of length {length}...\n")
    print_password_policy()
    print()

    for i in range(count):
        pwd = generate_password(length)
        result = validate_password(pwd)
        bar = _entropy_bar(result.entropy_bits)
        print(f"  {i + 1:>2}. {pwd}")
        print(f"       {bar}  {result.strength.value}, {result.entropy_bits:.0f} bits\n")

    return 0


def _entropy_bar(entropy: float, width: int = 20) -> str:
    filled = min(int(entropy / 5), width)
    empty = width - filled
    if entropy >= 80:
        color, reset = "\033[92m", "\033[0m"
    elif entropy >= 60:
        color, reset = "\033[93m", "\033[0m"
    else:
        color, reset = "\033[91m", "\033[0m"
    bar = f"{color}{'█' * filled}{'░' * empty}{reset}"
    return f"[{bar}]"




def cmd_hide(args: argparse.Namespace) -> int:
    archive_path = Path(args.archive).resolve()
    cover_path   = Path(args.image).resolve()
    output_path  = Path(args.output).resolve()

    try:
        hide_file_in_image(
            archive_path=archive_path,
            cover_image_path=cover_path,
            output_image_path=output_path,
            channels=args.channels,
            bits=args.bits,
        )
    except (FileNotFoundError, ValueError, IOError) as exc:
        print(f"\n[✗] Embedding error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    stego_path  = Path(args.image).resolve()
    output_path = Path(args.output).resolve()

    try:
        extract_file_from_image(
            stego_image_path=stego_path,
            output_archive_path=output_path,
            channels=args.channels,
            bits=args.bits,
        )
    except (FileNotFoundError, ValueError, IOError) as exc:
        print(f"\n[✗] Extraction error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_imginfo(args: argparse.Namespace) -> int:
    try:
        image_info(Path(args.image).resolve())
    except (FileNotFoundError, ValueError) as exc:
        print(f"[✗] Error: {exc}", file=sys.stderr)
        return 1
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure_archive",
        description="SARC — secure archiver with AES-256 encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Packing:
    python main.py pack ./my_folder archive.sarc
    python main.py pack ./my_folder archive.sarc --lzma --iterations 300000

  Unpacking:
    python main.py unpack archive.sarc ./output_folder
        """,
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    pack_parser = subparsers.add_parser(
        "pack",
        help="Pack directory into archive",
        description="Packs directory into encrypted .sarc archive",
    )
    pack_parser.add_argument("source", metavar="FOLDER", help="Source directory")
    pack_parser.add_argument("archive", metavar="ARCHIVE", help="Path to archive being created")
    pack_parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_KDF_ITERATIONS,
        metavar="N",
        help=f"PBKDF2 iterations (default {DEFAULT_KDF_ITERATIONS:,})",
    )
    pack_parser.add_argument(
        "--lzma",
        action="store_true",
        help="Use LZMA instead of zlib (slower, better compression)",
    )
    pack_parser.add_argument(
        "--password",
        metavar="PASSWORD",
        default=None,
        help="Password (insecure! better to enter interactively)",
    )

    unpack_parser = subparsers.add_parser(
        "unpack",
        help="Unpack archive to directory",
        description="Unpacks and verifies .sarc archive",
    )
    unpack_parser.add_argument("archive", metavar="ARCHIVE", help="Path to .sarc archive")
    unpack_parser.add_argument("output", metavar="FOLDER", help="Directory for unpacking")
    unpack_parser.add_argument(
        "--password",
        metavar="PASSWORD",
        default=None,
        help="Password (insecure! better to enter interactively)",
    )

    genpass_parser = subparsers.add_parser(
        "genpass",
        help="Generate strong password",
        description="Generates cryptographically strong passwords and assesses their strength",
    )
    genpass_parser.add_argument(
        "--count",
        type=int,
        default=3,
        metavar="N",
        help="Number of passwords to generate (default 3)",
    )
    genpass_parser.add_argument(
        "--length",
        type=int,
        default=20,
        metavar="L",
        help=f"Password length from {MIN_LENGTH} to {MAX_LENGTH} (default 20)",
    )
    genpass_parser.add_argument(
        "--validate",
        metavar="PASSWORD",
        default=None,
        help="Validate specified password instead of generating",
    )


    hide_parser = subparsers.add_parser(
        "hide",
        help="Hide archive inside PNG image (LSB steganography)",
        description=(
            "Embeds .sarc archive into PNG image using LSB method.\n"
            "Resulting image is visually identical to original.\n"
            "IMPORTANT: always saved as PNG (JPEG would destroy hidden data)."
        ),
    )
    hide_parser.add_argument("archive",  metavar="ARCHIVE",      help="Path to .sarc archive")
    hide_parser.add_argument("image",    metavar="IMAGE", help="Source cover image")
    hide_parser.add_argument("output",   metavar="OUTPUT",       help="Output PNG with hidden archive")
    hide_parser.add_argument(
        "--channels", type=int, default=3, metavar="N",
        help="Channels for LSB: 1=R, 2=RG, 3=RGB, 4=RGBA (default 3)",
    )
    hide_parser.add_argument(
        "--bits", type=int, default=1, metavar="N",
        help="Bits per channel: 1 (undetectable) … 4 (holds more, default 1)",
    )

    reveal_parser = subparsers.add_parser(
        "reveal",
        help="Extract archive from stego image",
        description="Extracts previously embedded .sarc archive from PNG image.",
    )
    reveal_parser.add_argument("image",  metavar="IMAGE", help="PNG image with hidden archive")
    reveal_parser.add_argument("output", metavar="ARCHIVE",        help="Where to save extracted archive")
    reveal_parser.add_argument(
        "--channels", type=int, default=3, metavar="N",
        help="Must match --channels during hide (default 3)",
    )
    reveal_parser.add_argument(
        "--bits", type=int, default=1, metavar="N",
        help="Must match --bits during hide (default 1)",
    )

    imginfo_parser = subparsers.add_parser(
        "imginfo",
        help="Show image capacity for steganography",
        description="Displays capacity table for different LSB settings.",
    )
    imginfo_parser.add_argument("image", metavar="IMAGE", help="Path to image")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "pack":
        exit_code = cmd_pack(args)
    elif args.command == "unpack":
        exit_code = cmd_unpack(args)
    elif args.command == "genpass":
        exit_code = cmd_genpass(args)
    elif args.command == "hide":
        exit_code = cmd_hide(args)
    elif args.command == "reveal":
        exit_code = cmd_reveal(args)
    elif args.command == "imginfo":
        exit_code = cmd_imginfo(args)
    else:
        parser.print_help()
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
