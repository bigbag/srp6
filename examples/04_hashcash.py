#!/usr/bin/env python3
"""
Example 04: Hash Cash Proof of Work

This example demonstrates the hash cash proof-of-work system, which can be used
for rate limiting authentication attempts. The client must solve a computational
puzzle before the server will process the authentication request.

Hash cash works by finding a string that, when hashed, produces a hash with
a certain number of leading zero bits. The difficulty (bits) determines how
much computation is required.

Usage:
    python examples/04_hashcash.py
"""

import time

from srp6 import generate_hashcash, verify_hashcash


def benchmark_hashcash(bits: int, challenge: str) -> tuple[str, float]:
    """
    Generate hashcash and measure time taken.

    Returns:
        Tuple of (hashcash_string, time_in_ms)
    """
    start = time.perf_counter()
    hashcash = generate_hashcash(bits, challenge)
    end = time.perf_counter()
    return hashcash, (end - start) * 1000


def main():
    print("=" * 70)
    print("Hash Cash Proof of Work Example")
    print("=" * 70)
    print()

    print("Hash cash is used for rate limiting authentication endpoints.")
    print("The client must solve a computational puzzle before authentication.")
    print()

    challenge = "auth_challenge_abc123"

    print(f"Challenge string: {challenge}")
    print()

    # Demonstrate different difficulty levels
    print("Difficulty Benchmark:")
    print("-" * 70)
    print(f"{'Bits':<8} {'Time (ms)':<15} {'Hash Cash'}")
    print("-" * 70)

    for bits in [8, 10, 12, 14, 16]:
        hashcash, time_ms = benchmark_hashcash(bits, challenge)
        # Truncate hashcash for display
        display_hc = hashcash if len(hashcash) < 40 else hashcash[:40] + "..."
        print(f"{bits:<8} {time_ms:<15.2f} {display_hc}")

    print("-" * 70)
    print()
    print("Note: Time increases exponentially with each additional bit!")
    print()

    # Detailed example
    print("=" * 70)
    print("Detailed Example (11 bits)")
    print("=" * 70)
    print()

    bits = 11
    hashcash, time_ms = benchmark_hashcash(bits, challenge)

    print(f"Generated hash cash: {hashcash}")
    print(f"Time taken: {time_ms:.2f}ms")
    print()

    # Parse the hashcash format
    parts = hashcash.split(":")
    print("Hash cash format: version:bits:date:challenge:counter")
    print(f"  - Version:   {parts[0]}")
    print(f"  - Bits:      {parts[1]}")
    print(f"  - Date:      {parts[2]}")
    print(f"  - Challenge: {parts[3]}")
    print(f"  - Counter:   {parts[4]}")
    print()

    # Verification
    print("Verification:")
    print("-" * 70)

    # Verify with correct bits
    is_valid = verify_hashcash(hashcash, bits)
    print(f"verify_hashcash(hashcash, {bits}) = {is_valid}")

    # Verify with higher bits (should fail)
    is_valid_higher = verify_hashcash(hashcash, bits + 5)
    print(f"verify_hashcash(hashcash, {bits + 5}) = {is_valid_higher}")
    print()

    # Server-side usage example
    print("=" * 70)
    print("Server-Side Usage Pattern")
    print("=" * 70)
    print()

    print("""
# Server generates challenge and required bits
challenge = generate_challenge()  # e.g., random string + timestamp
required_bits = 11

# Send to client: {"challenge": challenge, "bits": required_bits}

# Client computes proof of work
hashcash = generate_hashcash(required_bits, challenge)

# Client sends hashcash with authentication request

# Server verifies before processing authentication
if verify_hashcash(hashcash, required_bits):
    # Process authentication request
    pass
else:
    # Reject request
    pass
""")

    print("This prevents brute-force attacks by requiring computational work")
    print("for each authentication attempt.")


if __name__ == "__main__":
    main()
