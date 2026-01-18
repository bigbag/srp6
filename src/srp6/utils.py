"""
Cryptographic utility functions for SRP implementation.
"""

import hashlib
import secrets


def hash_sha256(data: bytes) -> bytes:
    """Hash data using SHA-256."""
    return hashlib.sha256(data).digest()


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to big-endian integer."""
    return int.from_bytes(b, "big")


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    """
    Convert integer to big-endian bytes.

    Args:
        n: The integer to convert
        length: Optional fixed length. If None, uses minimum bytes needed.

    Raises:
        ValueError: If n is negative
    """
    if n < 0:
        raise ValueError("Cannot convert negative integer to bytes")
    if length is None:
        length = (n.bit_length() + 7) // 8
        if length == 0:
            length = 1
    return n.to_bytes(length, "big")


def pad(x: int, n: int) -> bytes:
    """
    Pad integer to at least n bytes.

    Args:
        x: Integer to serialize
        n: Minimum number of bytes
    """
    b = int_to_bytes(x)
    if len(b) >= n:
        return b
    return b.rjust(n, b"\x00")


def generate_random_bytes(n: int) -> bytes:
    """Generate n cryptographically secure random bytes."""
    return secrets.token_bytes(n)


def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    """
    Derive key using PBKDF2 with SHA-256.

    Args:
        password: The password bytes
        salt: The salt bytes
        iterations: Number of iterations
        dklen: Derived key length in bytes
    """
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte sequences."""
    if len(a) != len(b):
        raise ValueError("Byte sequences must have equal length")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def to_hex(data: bytes) -> str:
    """Convert bytes to lowercase hex string."""
    return data.hex()


def from_hex(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def mod_pow(base: int, exp: int, mod: int) -> int:
    """
    Efficient modular exponentiation: base^exp mod mod

    Uses Python's built-in pow() which is optimized for this.
    """
    return pow(base, exp, mod)


def concat_bytes(*arrays: bytes) -> bytes:
    """Concatenate multiple byte sequences."""
    return b"".join(arrays)
