from __future__ import annotations

import hashlib
import hmac
import secrets


MIN_PBKDF2_ITERATIONS: int = 100_000
MAX_PBKDF2_ITERATIONS: int = 1_000_000
DEFAULT_PBKDF2_ITERATIONS: int = 100_000


def hash_password(password: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a secure random salt."""
    if iterations < MIN_PBKDF2_ITERATIONS or iterations > MAX_PBKDF2_ITERATIONS:
        raise ValueError(
            f"Iterations must be between {MIN_PBKDF2_ITERATIONS} and {MAX_PBKDF2_ITERATIONS}"
        )
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a stored PBKDF2 hash using constant-time comparison."""
    if not hashed_password or not plain_password:
        return False

    parts = hashed_password.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False

    try:
        iterations = int(parts[1])
        if iterations < MIN_PBKDF2_ITERATIONS or iterations > MAX_PBKDF2_ITERATIONS:
            return False
        salt = bytes.fromhex(parts[2])
        expected_hash = bytes.fromhex(parts[3])
    except (ValueError, TypeError):
        return False

    derived = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived, expected_hash)
