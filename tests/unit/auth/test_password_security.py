"""Unit tests for password security and PBKDF2 hashing."""

from __future__ import annotations

import pytest

from backend.auth.security import hash_password, verify_password


class TestPasswordSecurity:
    def test_hash_format_and_entropy(self):
        h1 = hash_password("SuperSecret123!")
        h2 = hash_password("SuperSecret123!")

        # Format: pbkdf2_sha256$iterations$salt$hash
        parts1 = h1.split("$")
        parts2 = h2.split("$")

        assert len(parts1) == 4
        assert parts1[0] == "pbkdf2_sha256"
        assert parts1[1] == "100000"
        # Salts must be random, so two hashes of the same password must differ
        assert parts1[2] != parts2[2]
        assert h1 != h2

    def test_verify_password_correct(self):
        pwd = "CorrectHorseBatteryStaple!"
        hashed = hash_password(pwd)
        assert verify_password(pwd, hashed) is True

    def test_verify_password_incorrect(self):
        hashed = hash_password("Secret123")
        assert verify_password("WrongPassword", hashed) is False
        assert verify_password("secret123", hashed) is False  # Case sensitivity
        assert verify_password("", hashed) is False

    def test_verify_password_malformed_hash(self):
        assert verify_password("Secret123", "") is False
        assert verify_password("Secret123", "plaintext_password") is False
        assert verify_password("Secret123", "pbkdf2_sha256$notanint$salt$hash") is False
        assert verify_password("Secret123", "pbkdf2_sha256$100000$nothex$nothex") is False
        assert verify_password("Secret123", "unknown_alg$100000$salt$hash") is False

    def test_verify_password_iterations_below_minimum_fails(self):
        salt = "a" * 32
        hash_val = "b" * 64
        # Below 100,000 iterations must be rejected
        assert verify_password("Secret123", f"pbkdf2_sha256$99999${salt}${hash_val}") is False
        assert verify_password("Secret123", f"pbkdf2_sha256$1000${salt}${hash_val}") is False
        assert verify_password("Secret123", f"pbkdf2_sha256$0${salt}${hash_val}") is False
        assert verify_password("Secret123", f"pbkdf2_sha256$-500${salt}${hash_val}") is False

    def test_verify_password_iterations_above_maximum_fails(self):
        salt = "a" * 32
        hash_val = "b" * 64
        # Above 1,000,000 iterations must be rejected
        assert verify_password("Secret123", f"pbkdf2_sha256$1000001${salt}${hash_val}") is False
        assert verify_password("Secret123", f"pbkdf2_sha256$10000000${salt}${hash_val}") is False

    def test_hash_password_iteration_bounds(self):
        with pytest.raises(ValueError, match="Iterations must be between"):
            hash_password("Secret123", iterations=99_999)

        with pytest.raises(ValueError, match="Iterations must be between"):
            hash_password("Secret123", iterations=1_000_001)

        # Valid custom iteration count within bounds works
        h = hash_password("Secret123", iterations=150_000)
        assert verify_password("Secret123", h) is True
