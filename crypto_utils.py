import os
import hashlib
import hmac
import secrets
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

AES_KEY_SIZE: int = 32
AES_IV_SIZE: int = 16
SALT_SIZE: int = 32


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def generate_iv() -> bytes:
    return os.urandom(AES_IV_SIZE)


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    if iterations < 100_000:
        raise ValueError("Iteration count must be at least 100,000.")

    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=iterations,
        dklen=AES_KEY_SIZE,
    )
    return key


def encrypt(data: bytes, key: bytes) -> bytes:
    iv = generate_iv()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) < AES_IV_SIZE:
        raise ValueError("Encrypted block too short.")

    iv = data[:AES_IV_SIZE]
    ciphertext = data[AES_IV_SIZE:]

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()

    try:
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as exc:
        raise ValueError(f"Decryption error (wrong password?): {exc}") from exc

    unpadder = sym_padding.PKCS7(128).unpadder()
    try:
        plain = unpadder.update(padded_plain) + unpadder.finalize()
    except Exception as exc:
        raise ValueError(f"Padding removal error (wrong password?): {exc}") from exc

    return plain


def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
