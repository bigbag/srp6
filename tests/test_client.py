"""Tests for SRP client."""

from dataclasses import FrozenInstanceError

import pytest

from srp6 import (
    DEFAULT_GROUP,
    GROUPS,
    SRP_1024,
    SRP_1536,
    SRP_2048,
    SRP_3072,
    SRP_4096,
    SRP_6144,
    SRP_8192,
    SRPClient,
    generate_hashcash,
    pbkdf2_sha256,
    verify_hashcash,
)


class TestSRPClient:
    def test_client_creation(self, test_username: bytes):
        client = SRPClient(test_username)
        assert client.username == test_username
        assert client.group == DEFAULT_GROUP

    def test_client_empty_username_raises(self):
        with pytest.raises(ValueError, match="Username cannot be empty"):
            SRPClient(b"")

    def test_client_with_group_int(self, test_username: bytes):
        client = SRPClient(test_username, group=1024)
        assert client.group == SRP_1024

        client = SRPClient(test_username, group=2048)
        assert client.group == SRP_2048

        client = SRPClient(test_username, group=4096)
        assert client.group == SRP_4096

    def test_client_with_group_instance(self, test_username: bytes):
        client = SRPClient(test_username, group=SRP_4096)
        assert client.group == SRP_4096

    def test_client_invalid_group_size(self, test_username: bytes):
        with pytest.raises(ValueError, match="Invalid group size"):
            SRPClient(test_username, group=512)

    def test_client_invalid_group_type(self, test_username: bytes):
        with pytest.raises(ValueError, match="Invalid group type"):
            SRPClient(test_username, group="invalid")  # type: ignore

    def test_public_ephemeral_generated(self, test_username: bytes):
        client = SRPClient(test_username)
        A = client.get_public_ephemeral()
        assert isinstance(A, bytes)
        assert len(A) > 0

    def test_password_setter(self, test_username: bytes, test_password: bytes, test_salt: bytes):
        client = SRPClient(test_username)
        derived = pbkdf2_sha256(test_password, test_salt, iterations=1000)
        client.password = derived
        assert client.password == derived

    def test_deterministic_with_fixed_a(self, test_username: bytes):
        fixed_a = 12345678901234567890
        client1 = SRPClient(test_username, a=fixed_a)
        client2 = SRPClient(test_username, a=fixed_a)
        assert client1.get_public_ephemeral() == client2.get_public_ephemeral()


class TestSRPGroups:
    def test_groups_dict(self):
        assert 1024 in GROUPS
        assert 1536 in GROUPS
        assert 2048 in GROUPS
        assert 3072 in GROUPS
        assert 4096 in GROUPS
        assert 6144 in GROUPS
        assert 8192 in GROUPS
        assert GROUPS[1024] == SRP_1024
        assert GROUPS[1536] == SRP_1536
        assert GROUPS[2048] == SRP_2048
        assert GROUPS[3072] == SRP_3072
        assert GROUPS[4096] == SRP_4096
        assert GROUPS[6144] == SRP_6144
        assert GROUPS[8192] == SRP_8192

    def test_group_n_bytes(self):
        assert SRP_1024.N_bytes == 128
        assert SRP_1536.N_bytes == 192
        assert SRP_2048.N_bytes == 256
        assert SRP_3072.N_bytes == 384
        assert SRP_4096.N_bytes == 512
        assert SRP_6144.N_bytes == 768
        assert SRP_8192.N_bytes == 1024

    def test_group_generator(self):
        assert SRP_1024.g == 2
        assert SRP_1536.g == 2
        assert SRP_2048.g == 2
        assert SRP_3072.g == 2
        assert SRP_4096.g == 2
        assert SRP_6144.g == 2
        assert SRP_8192.g == 2

    def test_default_group(self):
        assert DEFAULT_GROUP == SRP_2048

    def test_srp_group_frozen(self):
        with pytest.raises(FrozenInstanceError):
            SRP_2048.N = 0  # type: ignore


class TestHashCash:
    def test_generate_and_verify(self):
        bits = 8  # Use small value for fast tests
        challenge = "test_challenge"
        hashcash = generate_hashcash(bits, challenge)

        assert isinstance(hashcash, str)
        assert verify_hashcash(hashcash, bits)

    def test_verify_fails_with_wrong_bits(self):
        bits = 8
        challenge = "test_challenge"
        hashcash = generate_hashcash(bits, challenge)

        # Should fail with higher bits requirement
        assert not verify_hashcash(hashcash, bits + 8)

    def test_hashcash_format(self):
        bits = 8
        challenge = "test"
        hashcash = generate_hashcash(bits, challenge)

        parts = hashcash.split(":")
        assert len(parts) == 5
        assert parts[0] == "1"  # version
        assert parts[1] == str(bits)
        assert parts[3] == challenge


class TestUtilities:
    def test_pbkdf2_sha256(self):
        password = b"password"
        salt = b"salt"
        result = pbkdf2_sha256(password, salt, iterations=1000)
        assert isinstance(result, bytes)
        assert len(result) == 32  # Default dklen

    def test_pbkdf2_sha256_custom_length(self):
        password = b"password"
        salt = b"salt"
        result = pbkdf2_sha256(password, salt, iterations=1000, dklen=64)
        assert len(result) == 64
