#!/usr/bin/env python3
"""
Example 01: User Registration (Signup)

This example demonstrates the first step of SRP6 authentication - user registration.
During signup, the server generates a salt and computes a password verifier that
will be stored in the database. The actual password is never stored.

Usage:
    python examples/01_signup.py
"""

from srp6 import SRP_2048, generate_random_bytes, hash_sha256, pbkdf2_sha256, to_hex
from srp6.utils import bytes_to_int, mod_pow

# Simulated user input (in real app, this comes from a registration form)
USERNAME = b"alice@example.com"
PASSWORD = b"password123"


def generate_salt(length: int = 16) -> bytes:
    """Generate a random salt for the user."""
    return generate_random_bytes(length)


def generate_verifier(username: bytes, password: bytes, salt: bytes, iterations: int = 10000) -> int:
    """
    Generate the password verifier v = g^x mod N.

    The verifier is what gets stored in the database instead of the password.
    Even if the database is compromised, the attacker cannot recover the password.

    Args:
        username: User's identifier
        password: User's plain text password
        salt: Random salt for this user
        iterations: PBKDF2 iterations for key derivation

    Returns:
        The verifier as an integer
    """
    group = SRP_2048

    # Derive the password using PBKDF2
    derived_password = pbkdf2_sha256(password, salt, iterations=iterations)

    # Compute x = H(salt || H(":" || password))
    # This is the GSA mode computation
    inner_hash = hash_sha256(b":" + derived_password)
    x = bytes_to_int(hash_sha256(salt + inner_hash))

    # Compute verifier v = g^x mod N
    verifier = mod_pow(group.g, x, group.N)

    return verifier


def main():
    print("=" * 60)
    print("SRP-6a User Registration Example")
    print("=" * 60)
    print()

    # Step 1: Generate a random salt for this user
    salt = generate_salt()
    print(f"Username: {USERNAME.decode()}")
    print(f"Password: {'*' * len(PASSWORD)}")
    print()

    # Step 2: Generate the password verifier
    verifier = generate_verifier(USERNAME, PASSWORD, salt)

    print("Generated credentials to store in database:")
    print("-" * 60)
    print(f"Salt (s):     {to_hex(salt)}")
    print(f"Verifier (v): {hex(verifier)[:64]}...")
    print(f"              ({verifier.bit_length()} bits)")
    print("-" * 60)
    print()

    print("These values should be stored in your database:")
    print("  - username (for lookup)")
    print("  - salt (s)")
    print("  - verifier (v)")
    print()
    print("The password is NEVER stored!")
    print()
    print("Next step: Run 02_authentication.py to see the login flow.")


if __name__ == "__main__":
    main()
