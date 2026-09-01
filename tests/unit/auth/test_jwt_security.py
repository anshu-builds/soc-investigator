"""Unit tests for JWT generation, validation, and attack resistance."""

from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import timedelta

import pytest

from backend.auth.jwt import (
    JWTError,
    _base64url_decode,
    _base64url_encode,
    create_access_token,
    decode_access_token,
)


class TestJWTSecurity:
    def test_valid_token_roundtrip(self):
        user_id = uuid.uuid4()
        email = "analyst@soc.corp"
        role = "analyst"

        token = create_access_token(user_id, email, role, secret_key="test-key-32-chars-long-secure!!")
        payload = decode_access_token(token, secret_key="test-key-32-chars-long-secure!!")

        assert payload["sub"] == str(user_id)
        assert payload["email"] == email
        assert payload["role"] == "analyst"
        assert payload["type"] == "access"
        assert payload["exp"] > int(time.time())

    def test_expired_token_rejected(self):
        user_id = uuid.uuid4()
        token = create_access_token(
            user_id,
            "analyst@soc.corp",
            "analyst",
            expires_delta=timedelta(seconds=-10),  # Expired in past
            secret_key="test-key-32-chars-long-secure!!",
        )
        with pytest.raises(JWTError, match="Token has expired"):
            decode_access_token(token, secret_key="test-key-32-chars-long-secure!!")

    def test_tampered_payload_rejected(self):
        user_id = uuid.uuid4()
        token = create_access_token(user_id, "analyst@soc.corp", "analyst", secret_key="test-key-32-chars-long-secure!!")
        parts = token.split(".")

        # Attacker modifies role from 'analyst' to 'admin' in payload
        payload = json.loads(_base64url_decode(parts[1]).decode("utf-8"))
        payload["role"] = "admin"
        tampered_payload_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))

        tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"

        with pytest.raises(JWTError, match="Invalid JWT signature"):
            decode_access_token(tampered_token, secret_key="test-key-32-chars-long-secure!!")

    def test_wrong_secret_key_rejected(self):
        token = create_access_token(uuid.uuid4(), "analyst@soc.corp", "analyst", secret_key="correct-key-32-chars-long-sec!!")
        with pytest.raises(JWTError, match="Invalid JWT signature"):
            decode_access_token(token, secret_key="wrong-key-32-chars-long-secret!!")

    def test_algorithm_confusion_none_rejected(self):
        # Attacker crafts token with alg: none
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "attacker@evil.com",
            "role": "admin",
            "type": "access",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        h_b64 = _base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))
        unsigned_token = f"{h_b64}.{p_b64}."

        with pytest.raises(JWTError, match="Unsupported JWT algorithm or type"):
            decode_access_token(unsigned_token, secret_key="test-key-32-chars-long-secure!!")

    def test_invalid_token_type_rejected(self):
        # Token with type != "access"
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "user@test.com",
            "role": "analyst",
            "type": "refresh",  # Not access
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        h_b64 = _base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))
        import hmac, hashlib
        sig = _base64url_encode(hmac.new(b"secret-key", f"{h_b64}.{p_b64}".encode("utf-8"), hashlib.sha256).digest())
        token = f"{h_b64}.{p_b64}.{sig}"

        with pytest.raises(JWTError, match="Invalid token type"):
            decode_access_token(token, secret_key="secret-key")

    def test_malformed_token_strings_rejected(self):
        for bad_token in ["", "not-a-jwt", "part1.part2", "part1.part2.part3.part4", None]:
            with pytest.raises(JWTError):
                decode_access_token(bad_token, secret_key="secret-key")

    def test_missing_iat_rejected(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "user@test.com",
            "role": "analyst",
            "type": "access",
            "exp": int(time.time()) + 3600,
            # iat missing
        }
        h_b64 = _base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))
        import hmac, hashlib
        sig = _base64url_encode(hmac.new(b"secret-key", f"{h_b64}.{p_b64}".encode("utf-8"), hashlib.sha256).digest())
        token = f"{h_b64}.{p_b64}.{sig}"

        with pytest.raises(JWTError, match="Missing token issued-at"):
            decode_access_token(token, secret_key="secret-key")

    def test_non_numeric_iat_rejected(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "user@test.com",
            "role": "analyst",
            "type": "access",
            "iat": "not-a-number",
            "exp": int(time.time()) + 3600,
        }
        h_b64 = _base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))
        import hmac, hashlib
        sig = _base64url_encode(hmac.new(b"secret-key", f"{h_b64}.{p_b64}".encode("utf-8"), hashlib.sha256).digest())
        token = f"{h_b64}.{p_b64}.{sig}"

        with pytest.raises(JWTError, match="Invalid token issued-at format"):
            decode_access_token(token, secret_key="secret-key")

    def test_future_iat_rejected(self):
        header = {"alg": "HS256", "typ": "JWT"}
        now = int(time.time())
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "user@test.com",
            "role": "analyst",
            "type": "access",
            "iat": now + 3600,  # 1 hour in the future
            "exp": now + 7200,
        }
        h_b64 = _base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))
        import hmac, hashlib
        sig = _base64url_encode(hmac.new(b"secret-key", f"{h_b64}.{p_b64}".encode("utf-8"), hashlib.sha256).digest())
        token = f"{h_b64}.{p_b64}.{sig}"

        with pytest.raises(JWTError, match="Token issued in the future"):
            decode_access_token(token, secret_key="secret-key")

    def test_exp_equal_to_now_rejected(self):
        header = {"alg": "HS256", "typ": "JWT"}
        now = int(time.time())
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "user@test.com",
            "role": "analyst",
            "type": "access",
            "iat": now - 3600,
            "exp": now,  # Exact boundary: exp == now must be rejected
        }
        h_b64 = _base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))
        import hmac, hashlib
        sig = _base64url_encode(hmac.new(b"secret-key", f"{h_b64}.{p_b64}".encode("utf-8"), hashlib.sha256).digest())
        token = f"{h_b64}.{p_b64}.{sig}"

        with pytest.raises(JWTError, match="Token has expired"):
            decode_access_token(token, secret_key="secret-key")

    def test_non_numeric_exp_rejected(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "user@test.com",
            "role": "analyst",
            "type": "access",
            "iat": int(time.time()),
            "exp": "never",
        }
        h_b64 = _base64url_encode(json.dumps(header).encode("utf-8"))
        p_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))
        import hmac, hashlib
        sig = _base64url_encode(hmac.new(b"secret-key", f"{h_b64}.{p_b64}".encode("utf-8"), hashlib.sha256).digest())
        token = f"{h_b64}.{p_b64}.{sig}"

        with pytest.raises(JWTError, match="Invalid token expiration format"):
            decode_access_token(token, secret_key="secret-key")
