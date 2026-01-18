"""
SRP-6a client implementation with GSA mode support.

"""

from .constants import DEFAULT_GROUP, GROUPS, SRPGroup
from .utils import bytes_to_int, concat_bytes, generate_random_bytes, hash_sha256, int_to_bytes, mod_pow, pad, xor_bytes


class SRPClient:
    """
    SRP-6a client implementation for GSA authentication.

    The GSA mode has specific differences from standard SRP:
    - Identity (I) is not included when computing x
    - Generator g is padded to N_BYTES when computing H(g) for M1

    Supports 1024, 2048, and 4096-bit prime groups from RFC 5054.
    """

    def __init__(self, username: bytes, a: int | None = None, group: SRPGroup | int | None = None):
        """
        Initialize SRP client.

        Args:
            username: The username/identity bytes
            a: Optional private ephemeral value (for testing). If None, random value is used.
            group: SRP group to use. Can be:
                   - SRPGroup instance
                   - int (1024, 2048, or 4096) for bit size
                   - None for default (2048-bit)

        Raises:
            ValueError: If username is empty or group is invalid
        """
        if not username:
            raise ValueError("Username cannot be empty")

        # Resolve group
        if group is None:
            self._group = DEFAULT_GROUP
        elif isinstance(group, int):
            if group not in GROUPS:
                raise ValueError(f"Invalid group size: {group}. Valid sizes: {list(GROUPS.keys())}")
            self._group = GROUPS[group]
        elif isinstance(group, SRPGroup):
            self._group = group
        else:
            raise ValueError(f"Invalid group type: {type(group)}")

        self.username = username
        self._password: bytes = b""  # Will be set later after server response

        # Shortcuts for group parameters
        N = self._group.N
        g = self._group.g
        N_bytes = self._group.N_bytes

        # Generate private ephemeral 'a' if not provided
        if a is None:
            self._a = bytes_to_int(generate_random_bytes(N_bytes))
        else:
            self._a = a

        # Compute public ephemeral A = g^a mod N
        self._A = mod_pow(g, self._a, N)

        # Compute k = H(N || pad(g, N_BYTES))
        # Note: N is NOT padded, only g is padded
        self._k = bytes_to_int(hash_sha256(concat_bytes(int_to_bytes(N), pad(g, N_bytes))))

        # Session key and proofs (computed during generate())
        self._K: bytes = b""
        self._M: bytes = b""

    @property
    def group(self) -> SRPGroup:
        """Get the SRP group being used."""
        return self._group

    @property
    def password(self) -> bytes:
        return self._password

    @password.setter
    def password(self, value: bytes):
        """Set the derived password (from PBKDF2)."""
        self._password = value

    def get_public_ephemeral(self) -> bytes:
        """Get the client's public ephemeral A value (not padded, for sending to server)."""
        return int_to_bytes(self._A)

    def generate(self, salt: bytes, server_public: bytes) -> bytes:
        """
        Generate the client proof M1 given server's salt and public ephemeral B.

        Args:
            salt: The salt from server
            server_public: Server's public ephemeral B (as bytes)

        Returns:
            The client proof M1

        Raises:
            ValueError: If server public key is invalid
        """
        N = self._group.N
        g = self._group.g
        N_bytes = self._group.N_bytes

        B = bytes_to_int(server_public)

        # Verify B mod N != 0
        if B % N == 0:
            raise ValueError("Invalid server public key")

        # Compute u = H(pad(A) || pad(B))
        u = bytes_to_int(hash_sha256(concat_bytes(pad(self._A, N_bytes), pad(B, N_bytes))))
        if u == 0:
            raise ValueError("Invalid server public key (u=0)")

        # Compute x = H(salt || H(":" || password))
        # In GSA mode, the identity is NOT included in the hash
        inner_hash = hash_sha256(concat_bytes(b":", self._password))
        x = bytes_to_int(hash_sha256(concat_bytes(salt, inner_hash)))

        # Compute S = (B - k * g^x)^(a + u*x) mod N
        t0 = (self._k * mod_pow(g, x, N)) % N
        t1 = (B - t0) % N
        t2 = self._a + u * x
        S = mod_pow(t1, t2, N)

        # Compute session key K = H(S)
        # Note: S is NOT padded
        self._K = hash_sha256(int_to_bytes(S))

        # Compute M1 = H(H(N) XOR H(g) || H(I) || salt || A || B || K)
        # In GSA mode:
        # - H(N) uses bytesFromBigint(N), NOT padded
        # - H(g) uses pad(g, N_BYTES)
        # - A and B are NOT padded
        h_N = hash_sha256(int_to_bytes(N))
        h_g = hash_sha256(pad(g, N_bytes))  # GSA mode: pad g
        h_I = hash_sha256(self.username)

        xor_hash = xor_bytes(h_N, h_g)

        self._M = hash_sha256(
            concat_bytes(
                xor_hash,
                h_I,
                salt,
                int_to_bytes(self._A),  # NOT padded
                int_to_bytes(B),  # NOT padded
                self._K,
            )
        )

        return self._M

    def generate_m2(self) -> bytes:
        """
        Generate M2 for GSA SRP verification.

        Returns:
            The M2 proof bytes
        """
        if not self._M:
            raise RuntimeError("M1 not generated yet")

        # Note: A is NOT padded
        return hash_sha256(concat_bytes(int_to_bytes(self._A), self._M, self._K))

    @property
    def session_key(self) -> bytes:
        """Get the computed session key K."""
        return self._K

    @property
    def M(self) -> bytes:
        """Get the client proof M1."""
        return self._M
