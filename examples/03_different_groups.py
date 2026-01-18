#!/usr/bin/env python3
"""
Example 03: Using Different Prime Groups

This example demonstrates how to use different prime group sizes (1024, 2048, 4096 bits).
Larger groups provide more security but are computationally more expensive.

Security recommendations:
- 1024-bit: Legacy only, NOT recommended for new applications
- 2048-bit: Standard, suitable for most applications (default)
- 4096-bit: High security, recommended for sensitive applications

Usage:
    python examples/03_different_groups.py
"""

import contextlib
import time

from srp6 import GROUPS, SRP_1024, SRP_2048, SRP_4096, SRPClient, pbkdf2_sha256

USERNAME = b"alice@example.com"
PASSWORD = b"password123"
SALT = b"fixed_salt_16byt"


def benchmark_group(group_size: int) -> float:
    """
    Benchmark SRP operations for a specific group size.

    Returns:
        Time taken in milliseconds
    """
    group = GROUPS[group_size]

    start = time.perf_counter()

    # Create client with specific group
    client = SRPClient(USERNAME, group=group)

    # Derive password
    derived = pbkdf2_sha256(PASSWORD, SALT, iterations=1000)
    client.password = derived

    # Get public ephemeral (exercises the modular exponentiation)
    client.get_public_ephemeral()

    # Simulate server response (using a fixed B for benchmarking)
    # In real usage, B would come from the server
    fake_B = (2 ** (group.N_bytes * 4)).to_bytes(group.N_bytes, "big")

    # Generate proof (will fail with fake B, but measures computation time)
    with contextlib.suppress(ValueError):
        client.generate(SALT, fake_B)

    end = time.perf_counter()
    return (end - start) * 1000


def main():
    print("=" * 60)
    print("SRP-6a Prime Groups Comparison")
    print("=" * 60)
    print()

    # Display group information
    print("Available Prime Groups:")
    print("-" * 60)
    print(f"{'Group':<12} {'Bits':<8} {'Bytes':<8} {'Security Level'}")
    print("-" * 60)
    print(f"{'SRP_1024':<12} {SRP_1024.N_bytes * 8:<8} {SRP_1024.N_bytes:<8} Legacy (not recommended)")
    print(f"{'SRP_2048':<12} {SRP_2048.N_bytes * 8:<8} {SRP_2048.N_bytes:<8} Standard (default)")
    print(f"{'SRP_4096':<12} {SRP_4096.N_bytes * 8:<8} {SRP_4096.N_bytes:<8} High security")
    print("-" * 60)
    print()

    # Benchmark each group
    print("Performance Benchmark:")
    print("-" * 60)

    for size in [1024, 2048, 4096]:
        # Warm up
        benchmark_group(size)

        # Actual benchmark (average of 3 runs)
        times = [benchmark_group(size) for _ in range(3)]
        avg_time = sum(times) / len(times)

        print(f"{size}-bit: {avg_time:.2f}ms average")

    print("-" * 60)
    print()

    # Example usage with different groups
    print("Usage Examples:")
    print("-" * 60)
    print()

    print("# Default (2048-bit):")
    print("client = SRPClient(b'user')")
    print()

    print("# Using 4096-bit for high security:")
    print("client = SRPClient(b'user', group=4096)")
    print("# or")
    print("client = SRPClient(b'user', group=SRP_4096)")
    print()

    print("# Using 1024-bit (legacy, not recommended):")
    print("client = SRPClient(b'user', group=1024)")
    print()

    # Demonstrate actual usage
    print("Creating clients with different groups:")
    print("-" * 60)

    for size in [1024, 2048, 4096]:
        client = SRPClient(USERNAME, group=size)
        A = client.get_public_ephemeral()
        print(f"{size}-bit: Public key A length = {len(A)} bytes")

    print()
    print("Recommendation: Use 2048-bit (default) or 4096-bit for new applications.")


if __name__ == "__main__":
    main()
