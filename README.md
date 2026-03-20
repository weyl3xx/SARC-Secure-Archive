# SARC - Secure Archive with AES-256 Encryption

SARC (Secure ARChive) is a Python-based encrypted archiver with steganography support. It provides military-grade encryption using AES-256-CBC and PBKDF2 key derivation, with optional LSB steganography to hide archives inside PNG images.

## Features

- **AES-256-CBC Encryption**: Military-grade encryption for archive contents
- **PBKDF2 Key Derivation**: Strong password-based key generation (default 200,000 iterations)
- **Compression**: zlib (fast) or LZMA (better compression ratio)
- **Integrity Verification**: SHA-256 hashing for all files and archive
- **Randomized Storage**: Files stored in random order with random padding
- **LSB Steganography**: Hide archives inside PNG images (visually imperceptible)
- **Password Security**: Built-in password generator and strength validator

## Installation

### Requirements

- Python 3.9+
- Required packages:
  ```bash
  pip install cryptography pillow
  ```

### Optional: Create virtual environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

pip install cryptography pillow
```

## Usage

### Basic Commands

#### Pack directory into encrypted archive
```bash
python main.py pack ./my_folder archive.sarc
```

#### Unpack archive
```bash
python main.py unpack archive.sarc ./output_folder
```

### Advanced Options

#### Use LZMA compression (better ratio, slower)
```bash
python main.py pack ./folder archive.sarc --lzma
```

#### Increase PBKDF2 iterations for stronger security
```bash
python main.py pack ./folder archive.sarc --iterations 500000
```

### Password Management

#### Generate strong passwords
```bash
python main.py genpass
python main.py genpass --count 5 --length 24
```

#### Validate password strength
```bash
python main.py genpass --validate "MyP@ssw0rd123"
```

### Steganography

#### Hide archive inside image
```bash
python main.py hide archive.sarc cover.png output.png
```

#### Extract archive from image
```bash
python main.py reveal stego.png extracted.sarc
```

#### Check image capacity
```bash
python main.py imginfo image.png
```

#### Steganography options
```bash
# Use more channels (higher capacity)
python main.py hide archive.sarc cover.png output.png --channels 4

# Use more bits per channel (higher capacity, more visible)
python main.py hide archive.sarc cover.png output.png --bits 2
```

## Archive Format

The .sarc archive uses the following structure:

```
┌──────────────────────────────────────────┐
│  HEADER  (80 bytes)                      │
│    magic        4 bytes   "SARC"         │
│    version      2 bytes   uint16         │
│    salt         32 bytes  random         │
│    kdf_iters    4 bytes   uint32         │
│    ft_offset    8 bytes   uint64         │
│    ft_size      8 bytes   uint64         │
│    reserved     22 bytes  zeros          │
├──────────────────────────────────────────┤
│  ENCRYPTED FILE TABLE                    │
│    (AES-256-CBC, JSON format)            │
├──────────────────────────────────────────┤
│  DATA BLOCKS  (random order)             │
│    encrypted + compressed files          │
│    random padding between blocks         │
├──────────────────────────────────────────┤
│  ARCHIVE HASH  (SHA-256, 32 bytes)       │
└──────────────────────────────────────────┘
```

## Password Requirements

- **Minimum length**: 12 characters
- **Maximum length**: 128 characters
- **Required characters**:
  - At least one uppercase letter (A-Z)
  - At least one lowercase letter (a-z)
  - At least one digit (0-9)
  - At least one special character (!@#$%^&*...)

## Security Features

1. **Strong Encryption**: AES-256-CBC with random IV for each block
2. **Key Derivation**: PBKDF2-HMAC-SHA256 with configurable iterations
3. **Integrity Protection**: SHA-256 hashing for all files and entire archive
4. **Anti-Analysis**: Random file order and random padding between blocks
5. **Path Traversal Protection**: Safe path handling during extraction

## Steganography Details

The LSB (Least Significant Bit) steganography method embeds data into the least significant bits of image pixels, making changes visually imperceptible.

### Capacity Calculation

- 1 RGB pixel = 3 channels
- With 1 bit per channel: 3 bits per pixel
- 1000×1000 image with 3 channels, 1 bit: ~375 KB capacity

### Parameters

- **channels**: 1-4 (1=R, 2=RG, 3=RGB, 4=RGBA)
- **bits**: 1-4 (bits per channel)
  - 1 bit: Visually perfect, minimal capacity
  - 2 bits: Almost undetectable, 2× capacity
  - 4 bits: May be noticeable on inspection, 4× capacity

## Module Overview

- `archive_format.py` - Binary format specification
- `compressor.py` - Data compression (zlib/LZMA)
- `crypto_utils.py` - Encryption and key derivation
- `packer.py` - Archive creation
- `unpacker.py` - Archive extraction and verification
- `password_utils.py` - Password generation and validation
- `steganography.py` - LSB steganography implementation
- `utils.py` - Helper utilities
- `main.py` - Command-line interface

## Examples

### Complete Workflow

```bash
# 1. Generate a strong password
python main.py genpass --length 20

# 2. Pack directory with LZMA compression
python main.py pack ./secret_docs archive.sarc --lzma

# 3. Hide archive in image
python main.py hide archive.sarc vacation.jpg hidden.png

# 4. Later: extract archive from image
python main.py reveal hidden.png recovered.sarc

# 5. Unpack archive
python main.py unpack recovered.sarc ./restored_docs
```

### Security-Focused Workflow

```bash
# Use maximum security settings
python main.py pack ./sensitive_data secure.sarc \
  --lzma \
  --iterations 1000000

# Verify password strength first
python main.py genpass --validate "YourChosenP@ssw0rd"
```

## Error Handling

The tool provides detailed error messages for:
- Wrong password
- Corrupted archives
- Integrity violations (SHA-256 mismatch)
- Path traversal attempts
- Insufficient image capacity
- Format errors

## Performance Notes

- **zlib**: Fast compression, good for most use cases
- **LZMA**: 2-3× better compression, but slower
- **PBKDF2 iterations**: Higher values = more secure but slower
  - 200,000: Default, good balance
  - 500,000+: High security, noticeably slower
  - 1,000,000: Maximum security, significant delay

## License

This project is provided as-is for educational purposes.

## Security Notice

This tool is designed for legitimate security purposes. Always:
- Use strong, unique passwords
- Store passwords securely (use a password manager)
- Test with non-critical data first
- Keep backups of important data
- Never share your password via insecure channels

## Contributing

Feel free to report issues or suggest improvements.
