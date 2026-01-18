"""
Hash Cash proof-of-work generator.

Hash cash is used for rate limiting on authentication endpoints.
The header contains a proof-of-work that satisfies the server's
requirements (specified by bits and challenge headers).
"""

import hashlib
from datetime import datetime, timezone


def generate_hashcash(bits: int, challenge: str) -> str:
    """
    Generate hash cash proof-of-work.

    The hash cash format is: version:bits:date:challenge:counter
    where we find a counter such that SHA1(hashcash) has 'bits' leading zeros.

    Args:
        bits: Number of leading zero bits required
        challenge: The challenge string

    Returns:
        The hash cash string
    """
    version = 1
    date = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    counter = 0

    while True:
        hc = f"{version}:{bits}:{date}:{challenge}:{counter}"

        # Compute SHA1 hash
        hash_hex = hashlib.sha1(hc.encode()).hexdigest()

        # Convert to binary and check leading zeros
        # SHA1 produces 160 bits
        hash_int = int(hash_hex, 16)
        binary_hash = bin(hash_int)[2:].zfill(160)

        # Check if first 'bits' characters are all zeros
        if all(c == "0" for c in binary_hash[:bits]):
            return hc

        counter += 1


def verify_hashcash(hashcash: str, bits: int) -> bool:
    """
    Verify a hash cash string.

    Note: Timing-safe comparison is not required here because hashcash is used
    for rate-limiting proof-of-work, not authentication. The hash value is derived
    from the client-provided hashcash string and contains no secrets. The comparison
    only reveals whether the hash has sufficient leading zeros, which is already
    evident from the hash itself.

    Args:
        hashcash: The hash cash string to verify
        bits: Required number of leading zero bits

    Returns:
        True if the hash cash is valid
    """
    hash_hex = hashlib.sha1(hashcash.encode()).hexdigest()
    hash_int = int(hash_hex, 16)
    binary_hash = bin(hash_int)[2:].zfill(160)
    return all(c == "0" for c in binary_hash[:bits])
