from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import timedelta
from typing import Any, Dict, Optional

from backend.config import get_settings


class JWTError(Exception):
    """Raised when JWT verification fails."""
    pass


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data_str: str) -> bytes:
    padding = 4 - (len(data_str) % 4)
    if padding != 4:
        data_str += "=" * padding
    return base64.urlsafe_b64decode(data_str.encode("ascii"))


MAX_CLOCK_SKEW_SECONDS: int = 10


def create_access_token(
    user_id: uuid.UUID | str,
    email: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
    secret_key: Optional[str] = None,
) -> str:
    """Create an HMAC-SHA256 signed JWT access token."""
    settings = get_settings()
    key = secret_key or settings.jwt_secret_key
    now = int(time.time())
    expire_seconds = int(expires_delta.total_seconds()) if expires_delta else settings.jwt_expire_minutes * 60
    exp = now + expire_seconds

    header = {"alg": "HS256", "typ": "JWT"}
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "role": role.lower(),
        "type": "access",
        "iat": now,
        "exp": exp,
    }

    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = _base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_access_token(token: str, secret_key: Optional[str] = None) -> Dict[str, Any]:
    """Decode and validate a JWT access token."""
    if not token or not isinstance(token, str):
        raise JWTError("Missing or invalid token format")

    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError("Invalid JWT segment count")

    header_b64, payload_b64, signature_b64 = parts

    # Decode and validate header
    try:
        header = json.loads(_base64url_decode(header_b64).decode("utf-8"))
    except Exception as e:
        raise JWTError(f"Invalid JWT header: {e}")

    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise JWTError("Unsupported JWT algorithm or type")

    # Verify signature
    settings = get_settings()
    key = secret_key or settings.jwt_secret_key
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()

    try:
        actual_sig = _base64url_decode(signature_b64)
    except Exception:
        raise JWTError("Invalid JWT signature encoding")

    if not hmac.compare_digest(actual_sig, expected_sig):
        raise JWTError("Invalid JWT signature")

    # Decode and validate payload
    try:
        payload = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
    except Exception as e:
        raise JWTError(f"Invalid JWT payload: {e}")

    now = int(time.time())

    # Validate expiration
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise JWTError("Invalid token expiration format")
    if now >= exp:
        raise JWTError("Token has expired")

    # Validate issued-at (iat)
    if "iat" not in payload:
        raise JWTError("Missing token issued-at (iat)")
    iat = payload["iat"]
    if not isinstance(iat, (int, float)):
        raise JWTError("Invalid token issued-at format")
    if iat > now + MAX_CLOCK_SKEW_SECONDS:
        raise JWTError("Token issued in the future")

    if payload.get("type") != "access":
        raise JWTError("Invalid token type")

    if not payload.get("sub"):
        raise JWTError("Missing token subject (user ID)")

    return payload
