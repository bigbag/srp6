"""Test fixtures for srp6."""

import pytest


@pytest.fixture
def test_username() -> bytes:
    return b"test@example.com"


@pytest.fixture
def test_password() -> bytes:
    return b"test_password"


@pytest.fixture
def test_salt() -> bytes:
    return b"random_salt_bytes_16"
