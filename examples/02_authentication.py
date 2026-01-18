#!/usr/bin/env python3
"""
Example 02: User Authentication (Login)

This example demonstrates the complete SRP-6a authentication handshake between
a client and server. The protocol ensures that:
- The password is never transmitted over the network
- Both parties can verify each other's identity
- A shared session key is established for secure communication

Usage:
    python examples/02_authentication.py
"""

from srp6 import SRP_2048, SRPClient, generate_random_bytes, hash_sha256, pbkdf2_sha256, to_hex
from srp6.utils import bytes_to_int, concat_bytes, int_to_bytes, mod_pow, pad, xor_bytes

# User credentials (same as in signup example)
USERNAME = b"alice@example.com"
PASSWORD = b"password123"
PBKDF2_ITERATIONS = 10000


class MockDatabase:
    """Simulates a database storing user credentials from registration."""

    def __init__(self):
        self.users: dict[bytes, dict] = {}

    def store_user(self, username: bytes, salt: bytes, verifier: int):
        self.users[username] = {"salt": salt, "verifier": verifier}

    def get_user(self, username: bytes) -> dict | None:
        return self.users.get(username)


class SRPServer:
    """
    SRP-6a server implementation.

    In a real application, this would run on your backend server.
    """

    def __init__(self, group=SRP_2048):
        self.group = group
        self._b: int | None = None  # Server's private ephemeral
        self._B: int | None = None  # Server's public ephemeral
        self._K: bytes | None = None  # Session key
        self._user: dict | None = None

    def start_handshake(self, user: dict) -> tuple[bytes, bytes]:
        """
        Start the authentication handshake.

        Args:
            user: User record from database containing salt and verifier

        Returns:
            Tuple of (salt, server_public_B) to send to client
        """
        self._user = user
        N = self.group.N
        g = self.group.g
        N_bytes = self.group.N_bytes

        # Generate server's private ephemeral b
        self._b = bytes_to_int(generate_random_bytes(N_bytes))

        # Compute k = H(N || pad(g, N_bytes))
        k = bytes_to_int(hash_sha256(concat_bytes(int_to_bytes(N), pad(g, N_bytes))))

        # Compute server's public ephemeral B = k*v + g^b mod N
        v = user["verifier"]
        self._B = (k * v + mod_pow(g, self._b, N)) % N

        return user["salt"], int_to_bytes(self._B)

    def verify_proof(self, client_public: bytes, client_proof: bytes) -> tuple[bool, bytes]:
        """
        Verify the client's proof M1 and generate server proof M2.

        Args:
            client_public: Client's public ephemeral A
            client_proof: Client's proof M1

        Returns:
            Tuple of (is_valid, server_proof_M2)
        """
        N = self.group.N
        g = self.group.g
        N_bytes = self.group.N_bytes

        A = bytes_to_int(client_public)
        v = self._user["verifier"]

        # Verify A mod N != 0
        if A % N == 0:
            return False, b""

        # Compute u = H(pad(A) || pad(B))
        u = bytes_to_int(hash_sha256(concat_bytes(pad(A, N_bytes), pad(self._B, N_bytes))))

        # Compute S = (A * v^u)^b mod N
        S = mod_pow(A * mod_pow(v, u, N), self._b, N)

        # Compute session key K = H(S)
        self._K = hash_sha256(int_to_bytes(S))

        # Compute expected M1 = H(H(N) XOR H(g) || H(I) || salt || A || B || K)
        h_N = hash_sha256(int_to_bytes(N))
        h_g = hash_sha256(pad(g, N_bytes))
        h_I = hash_sha256(self._user["username"])
        xor_hash = xor_bytes(h_N, h_g)

        expected_M1 = hash_sha256(
            concat_bytes(
                xor_hash,
                h_I,
                self._user["salt"],
                int_to_bytes(A),
                int_to_bytes(self._B),
                self._K,
            )
        )

        # Verify client proof
        if client_proof != expected_M1:
            return False, b""

        # Generate server proof M2 = H(A || M1 || K)
        M2 = hash_sha256(concat_bytes(int_to_bytes(A), client_proof, self._K))

        return True, M2

    @property
    def session_key(self) -> bytes:
        return self._K


def register_user(db: MockDatabase, username: bytes, password: bytes) -> None:
    """Register a new user (from example 01)."""
    salt = generate_random_bytes(16)
    derived_password = pbkdf2_sha256(password, salt, iterations=PBKDF2_ITERATIONS)

    inner_hash = hash_sha256(b":" + derived_password)
    x = bytes_to_int(hash_sha256(salt + inner_hash))
    verifier = mod_pow(SRP_2048.g, x, SRP_2048.N)

    db.store_user(username, salt, verifier)
    db.users[username]["username"] = username  # Store username for M1 computation


def main():
    print("=" * 70)
    print("SRP-6a Authentication Handshake Example")
    print("=" * 70)
    print()

    # Setup: Register the user (normally done during signup)
    db = MockDatabase()
    register_user(db, USERNAME, PASSWORD)
    print(f"[Setup] User '{USERNAME.decode()}' registered in database")
    print()

    # ========== STEP 1: Client initiates authentication ==========
    print("=" * 70)
    print("STEP 1: Client -> Server (Initiate)")
    print("=" * 70)

    # Client creates SRP client and sends username + public ephemeral A
    client = SRPClient(USERNAME)
    client_public_A = client.get_public_ephemeral()

    print("Client sends:")
    print(f"  - Username: {USERNAME.decode()}")
    print(f"  - Public key A: {to_hex(client_public_A)[:64]}...")
    print()

    # ========== STEP 2: Server responds with salt and B ==========
    print("=" * 70)
    print("STEP 2: Server -> Client (Challenge)")
    print("=" * 70)

    # Server looks up user and generates challenge
    user = db.get_user(USERNAME)
    if not user:
        print("ERROR: User not found!")
        return

    server = SRPServer()
    salt, server_public_B = server.start_handshake(user)

    print("Server sends:")
    print(f"  - Salt: {to_hex(salt)}")
    print(f"  - Public key B: {to_hex(server_public_B)[:64]}...")
    print()

    # ========== STEP 3: Client computes proof M1 ==========
    print("=" * 70)
    print("STEP 3: Client -> Server (Proof)")
    print("=" * 70)

    # Client derives password and computes proof
    derived_password = pbkdf2_sha256(PASSWORD, salt, iterations=PBKDF2_ITERATIONS)
    client.password = derived_password
    client_proof_M1 = client.generate(salt, server_public_B)

    print("Client computes and sends:")
    print(f"  - Proof M1: {to_hex(client_proof_M1)}")
    print()

    # ========== STEP 4: Server verifies and responds ==========
    print("=" * 70)
    print("STEP 4: Server -> Client (Verification)")
    print("=" * 70)

    # Server verifies client proof
    is_valid, server_proof_M2 = server.verify_proof(client_public_A, client_proof_M1)

    if is_valid:
        print("Server: Client proof VERIFIED!")
        print("Server sends:")
        print(f"  - Proof M2: {to_hex(server_proof_M2)}")
    else:
        print("Server: Client proof FAILED!")
        return
    print()

    # ========== STEP 5: Client verifies server proof ==========
    print("=" * 70)
    print("STEP 5: Client verifies server")
    print("=" * 70)

    expected_M2 = client.generate_m2()
    if server_proof_M2 == expected_M2:
        print("Client: Server proof VERIFIED!")
    else:
        print("Client: Server proof FAILED!")
        return
    print()

    # ========== SUCCESS: Both parties have the same session key ==========
    print("=" * 70)
    print("AUTHENTICATION SUCCESSFUL!")
    print("=" * 70)
    print()
    print(f"Client session key: {to_hex(client.session_key)}")
    print(f"Server session key: {to_hex(server.session_key)}")
    print()

    if client.session_key == server.session_key:
        print("Session keys MATCH - secure channel established!")
    else:
        print("ERROR: Session keys do not match!")


if __name__ == "__main__":
    main()
