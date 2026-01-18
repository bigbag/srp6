# srp6

[![CI](https://github.com/bigbag/srp6/workflows/CI/badge.svg)](https://github.com/bigbag/srp6/actions?query=workflow%3ACI)
[![pypi](https://img.shields.io/pypi/v/srp6.svg)](https://pypi.python.org/pypi/srp6)
[![downloads](https://img.shields.io/pypi/dm/srp6.svg)](https://pypistats.org/packages/srp6)
[![versions](https://img.shields.io/pypi/pyversions/srp6.svg)](https://github.com/bigbag/srp6)
[![license](https://img.shields.io/github/license/bigbag/srp6.svg)](https://github.com/bigbag/srp6/blob/master/LICENSE)

A pure Python implementation of the Secure Remote Password protocol (SRP version 6a) with GSA mode support.

## Overview

SRP (Secure Remote Password) is a password-authenticated key exchange protocol that allows secure authentication without transmitting the password over the network. This implementation follows RFC 5054 and includes support for GSA (Grand Slam Authentication) mode used by Apple services.

## Features

- **Pure Python** - No external dependencies, uses only Python standard library
- **Multiple Key Sizes** - Support for 1024 to 8192-bit primes from RFC 5054
- **GSA Mode** - Compatible with Apple's authentication services
- **Hash Cash** - Includes proof-of-work implementation for rate limiting
- **Type Hints** - Full type annotation support

## Installation

```bash
pip install srp6
```

## Usage

### Basic SRP Client

```python
from srp6 import SRPClient, pbkdf2_sha256

# Create client with username
client = SRPClient(b"user@example.com")

# Derive password using PBKDF2 (typically from server's salt)
password = b"secret_password"
salt = b"server_provided_salt"
derived_password = pbkdf2_sha256(password, salt, iterations=10000)
client.password = derived_password

# Get public ephemeral to send to server
A = client.get_public_ephemeral()

# After receiving server's salt and public ephemeral B:
# Generate client proof M1
M1 = client.generate(salt=server_salt, server_public=server_B)

# Get session key for encrypted communication
session_key = client.session_key
```

### Using Different Prime Groups

```python
from srp6 import SRPClient, SRP_1024, SRP_4096

# Use 1024-bit prime (faster, less secure)
client_1024 = SRPClient(b"user", group=1024)

# Use 4096-bit prime (slower, more secure)
client_4096 = SRPClient(b"user", group=4096)

# Or pass the group directly
client = SRPClient(b"user", group=SRP_4096)
```

### Hash Cash (Proof of Work)

```python
from srp6 import generate_hashcash, verify_hashcash

# Generate proof of work
bits = 11  # Difficulty level (number of leading zero bits)
challenge = "server_challenge_string"
hashcash = generate_hashcash(bits, challenge)

# Verify proof of work
is_valid = verify_hashcash(hashcash, bits)
```

## API Reference

### SRPClient

```python
class SRPClient:
    def __init__(
        self,
        username: bytes,
        a: int | None = None,
        group: SRPGroup | int | None = None
    ):
        """
        Initialize SRP client.

        Args:
            username: The username/identity bytes
            a: Optional private ephemeral value (for testing)
            group: SRP group - SRPGroup instance, bit size (1024/2048/4096), or None for default (2048)
        """
```

**Properties:**
- `password` - Set the derived password (from PBKDF2)
- `session_key` - Get the computed session key K
- `M` - Get the client proof M1
- `group` - Get the SRP group being used

**Methods:**
- `get_public_ephemeral()` - Get client's public ephemeral A
- `generate(salt, server_public)` - Generate client proof M1
- `generate_m2()` - Generate M2 for verification

### Prime Groups

All groups from RFC 5054 (1024 to 8192 bits):

- `SRP_1024` - 1024 bits (128 bytes) - Legacy, not recommended
- `SRP_1536` - 1536 bits (192 bytes) - Legacy
- `SRP_2048` - 2048 bits (256 bytes) - Standard (default)
- `SRP_3072` - 3072 bits (384 bytes) - Enhanced security
- `SRP_4096` - 4096 bits (512 bytes) - High security
- `SRP_6144` - 6144 bits (768 bytes) - Very high security
- `SRP_8192` - 8192 bits (1024 bytes) - Maximum security

### Utility Functions

```python
# Hashing
hash_sha256(data: bytes) -> bytes
pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes

# Byte conversions
bytes_to_int(b: bytes) -> int
int_to_bytes(n: int, length: int | None = None) -> bytes
to_hex(data: bytes) -> str
from_hex(hex_str: str) -> bytes
```

## GSA Mode

This implementation supports GSA (Grand Slam Authentication) mode, which differs from standard SRP-6a in the following ways:

1. **Identity not included in x computation** - The password verifier x is computed as `H(salt || H(":" || password))` instead of `H(salt || H(I || ":" || password))`

2. **Generator padding** - The generator g is padded to N_BYTES when computing `H(g)` for the M1 proof

3. **No padding for A, B, S** - The public ephemerals A and B, and the shared secret S are NOT padded in their respective computations

## Protocol Details

### Notation

- `N` - Large safe prime (N = 2q+1, where q is prime)
- `g` - Generator modulo N
- `k` - Multiplier parameter: `k = H(N || pad(g))`
- `s` - User's salt
- `I` - Username
- `p` - Cleartext password
- `H()` - One-way hash function (SHA-256)
- `x` - Private key derived from password and salt
- `v` - Password verifier stored on server
- `a`, `b` - Secret ephemeral values
- `A`, `B` - Public ephemeral values
- `S` - Premaster secret
- `K` - Session key
- `M1`, `M2` - Proofs

### Registration (One-Time Setup)

```
x = H(s || H(I || ":" || p))     # Private key
v = g^x % N                       # Verifier (stored on server)
```

The server stores: `(I, s, v)`. The password `p` is never stored.

### Authentication Handshake

```
Client                                  Server
------                                  ------
  |                                       |
  |  -------- I, A = g^a % N ------>      |
  |                                       |
  |  <------- s, B = kv + g^b % N --      |
  |                                       |
  |  u = H(pad(A) || pad(B))              |  u = H(pad(A) || pad(B))
  |  x = H(s || H(I || ":" || p))         |
  |  S = (B - kg^x)^(a + ux) % N          |  S = (Av^u)^b % N
  |  K = H(S)                             |  K = H(S)
  |                                       |
  |  -------- M1 = H(...) ---------->     |  (verify M1)
  |                                       |
  |  (verify M2) <------ M2 = H(...) --   |
  |                                       |
  |  [Session key K established]          |
```

### Client Calculations

1. Generate random `a`, compute `A = g^a % N`
2. Receive `s`, `B` from server
3. Compute `u = H(pad(A) || pad(B))`
4. Compute `k = H(N || pad(g))`
5. Derive `x = H(s || H(I || ":" || p))`
6. Compute `S = (B - k * g^x)^(a + u*x) % N`
7. Compute session key `K = H(S)`
8. Compute proof `M1 = H(H(N) XOR H(g) || H(I) || s || A || B || K)`

### Server Calculations

1. Look up `s`, `v` for user `I`
2. Generate random `b`, compute `B = k*v + g^b % N`
3. Receive `A` from client
4. Compute `u = H(pad(A) || pad(B))`
5. Compute `S = (A * v^u)^b % N`
6. Compute session key `K = H(S)`
7. Verify client proof `M1`
8. Compute server proof `M2 = H(A || M1 || K)`

### Security Safeguards

The protocol aborts if any of these conditions occur:

- **Client aborts** if `B % N == 0` (malicious server)
- **Client aborts** if `u == 0` (compromised exchange)
- **Server aborts** if `A % N == 0` (malicious client)
- **Server aborts** if client proof `M1` is invalid

## Protocol Flow Diagram

```
Client                                  Server
------                                  ------
  |                                       |
  |  -------- username, A -------->       |
  |                                       |
  |  <------- salt, B -------------       |
  |                                       |
  |  -------- M1 (proof) --------->       |
  |                                       |
  |  <------- M2 (verification) ---       |
  |                                       |
  |  [Session key K established]          |
```

## Examples

See the [examples](examples/) directory for complete working examples:

- [01_signup.py](examples/01_signup.py) - User registration, generating salt and verifier
- [02_authentication.py](examples/02_authentication.py) - Complete authentication handshake
- [03_different_groups.py](examples/03_different_groups.py) - Using different prime group sizes
- [04_hashcash.py](examples/04_hashcash.py) - Hash cash proof-of-work for rate limiting

Run examples:
```bash
python examples/01_signup.py
python examples/02_authentication.py
```

## References

- [RFC 2945 - The SRP Authentication and Key Exchange System](https://tools.ietf.org/html/rfc2945)
- [RFC 5054 - Using SRP for TLS Authentication](https://tools.ietf.org/html/rfc5054)
- [Stanford SRP Homepage](http://srp.stanford.edu/)

## License

MIT License - see [LICENSE](LICENSE) for details.
