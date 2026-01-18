"""
srp6 - Pure Python SRP-6a client implementation.

A safe implementation of the Secure Remote Password protocol (SRP version 6a)
with GSA mode support. Supports 1024, 2048, and 4096-bit prime groups from RFC 5054.

Example:
    >>> from srp6 import SRPClient
    >>> client = SRPClient(b"user@example.com")
    >>> client.password = derived_password  # From PBKDF2
    >>> A = client.get_public_ephemeral()
    >>> M1 = client.generate(salt, server_B)
"""

__version__ = "0.1.1"

from .client import SRPClient
from .constants import (
    DEFAULT_GROUP,
    GROUPS,
    SRP_1024,
    SRP_1536,
    SRP_2048,
    SRP_3072,
    SRP_4096,
    SRP_6144,
    SRP_8192,
    SRPGroup,
)
from .hashcash import generate_hashcash, verify_hashcash
from .utils import (
    bytes_to_int,
    from_hex,
    generate_random_bytes,
    hash_sha256,
    int_to_bytes,
    pbkdf2_sha256,
    to_hex,
)

__all__ = [
    # Version
    "__version__",
    # Client
    "SRPClient",
    # Groups
    "SRPGroup",
    "SRP_1024",
    "SRP_1536",
    "SRP_2048",
    "SRP_3072",
    "SRP_4096",
    "SRP_6144",
    "SRP_8192",
    "GROUPS",
    "DEFAULT_GROUP",
    # Hashcash
    "generate_hashcash",
    "verify_hashcash",
    # Utilities
    "hash_sha256",
    "pbkdf2_sha256",
    "generate_random_bytes",
    "bytes_to_int",
    "int_to_bytes",
    "to_hex",
    "from_hex",
]
