# srp6 Examples

This directory contains example scripts demonstrating how to use the srp6 library.

## Examples

- [01_signup.py](01_signup.py) - User registration, generating salt and verifier
- [02_authentication.py](02_authentication.py) - Complete authentication handshake between client and server
- [03_different_groups.py](03_different_groups.py) - Using different prime group sizes (1024, 2048, 4096 bits)
- [04_hashcash.py](04_hashcash.py) - Hash cash proof-of-work for rate limiting

## Running the Examples

Make sure you have the srp6 library installed:

```bash
pip install srp6
```

Or if running from the repository:

```bash
cd /path/to/srp6
pip install -e .
```

Then run any example:

```bash
python examples/01_signup.py
python examples/02_authentication.py
python examples/03_different_groups.py
python examples/04_hashcash.py
```

## Example Flow

For a complete understanding of SRP-6a authentication, run the examples in order:

1. **01_signup.py** - Shows how to register a user by generating salt and verifier
2. **02_authentication.py** - Demonstrates the full login handshake
3. **03_different_groups.py** - Explains security/performance tradeoffs
4. **04_hashcash.py** - Shows how to add rate limiting protection

## Protocol Overview

```
Registration (01_signup.py):
  Client                    Server
    |                         |
    |  -- username, password ->|  (over secure channel)
    |                         |
    |                    Generate salt (s)
    |                    Compute verifier v = g^x mod N
    |                    Store (username, s, v)
    |                         |

Authentication (02_authentication.py):
  Client                    Server
    |                         |
    |  ---- username, A ----> |  Step 1: Client initiates
    |                         |
    |  <----- s, B ---------- |  Step 2: Server challenge
    |                         |
    |  ---- M1 (proof) -----> |  Step 3: Client proof
    |                         |
    |  <---- M2 (proof) ----- |  Step 4: Server proof
    |                         |
    |  [Session key K established]
```
