"""In-memory sliding-window rate limiter and concurrency guard.

Architecture Notice:
This rate limiter is process-local and suitable for single-process async deployments.
For horizontally scaled multi-process or multi-container deployments, an external
centralized store (e.g. Redis) is required to coordinate limits across instances.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple
from fastapi import HTTPException, Request, status

import ipaddress
import socket
from backend.config import get_settings


class InMemoryRateLimiter:
    """Thread-safe and async-safe in-memory sliding-window rate limiter."""

    def __init__(self, max_tracked_keys: int = 10_000):
        self._records: Dict[str, Deque[float]] = defaultdict(deque)
        self._concurrency: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
        self._max_tracked_keys = max_tracked_keys
        self._last_cleanup = time.monotonic()

    async def check(
        self,
        key: str,
        limit: int,
        window_seconds: int = 60,
    ) -> Tuple[bool, int]:
        """Check if a request is allowed under the sliding window.

        Returns (allowed: bool, retry_after: int).
        """
        async with self._lock:
            now = time.monotonic()
            self._maybe_cleanup(now)

            timestamps = self._records[key]

            # Evict timestamps outside the sliding window
            cutoff = now - window_seconds
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= limit:
                oldest = timestamps[0]
                retry_after = max(1, int(oldest + window_seconds - now + 0.999))
                return False, retry_after

            timestamps.append(now)
            return True, 0

    async def acquire_concurrency(self, key: str, max_concurrent: int) -> bool:
        """Attempt to acquire a concurrency slot for a key."""
        async with self._lock:
            current = self._concurrency[key]
            if current >= max_concurrent:
                return False
            self._concurrency[key] = current + 1
            return True

    async def release_concurrency(self, key: str) -> None:
        """Release a previously acquired concurrency slot."""
        async with self._lock:
            current = self._concurrency[key]
            if current <= 1:
                self._concurrency.pop(key, None)
            else:
                self._concurrency[key] = current - 1

    def _maybe_cleanup(self, now: float) -> None:
        """Prune empty or stale keys to prevent unbounded memory growth."""
        if now - self._last_cleanup < 60 and len(self._records) < self._max_tracked_keys:
            return

        self._last_cleanup = now
        stale_cutoff = now - 300.0  # 5 minutes idle
        keys_to_remove = []

        for key, timestamps in self._records.items():
            while timestamps and timestamps[0] <= stale_cutoff:
                timestamps.popleft()
            if not timestamps:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            self._records.pop(key, None)

    def reset(self) -> None:
        """Reset internal state (useful for tests)."""
        self._records.clear()
        self._concurrency.clear()
        self._last_cleanup = time.monotonic()


# Process-wide singleton rate limiter
limiter = InMemoryRateLimiter()


def is_trusted_proxy(peer_ip: str, trusted_proxies_cfg: str) -> bool:
    """Verify if the immediate peer IP matches any configured trusted proxy."""
    if not trusted_proxies_cfg or not peer_ip:
        return False
    try:
        peer_addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False

    for item in trusted_proxies_cfg.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            if "/" in item:
                if peer_addr in ipaddress.ip_network(item, strict=False):
                    return True
            else:
                if peer_addr == ipaddress.ip_address(item):
                    return True
        except ValueError:
            # Check hostname equality or DNS resolution (e.g. 'nginx')
            if item.lower() == peer_ip.lower():
                return True
            try:
                resolved_ips = socket.gethostbyname_ex(item)[2]
                if peer_ip in resolved_ips:
                    return True
            except (socket.error, socket.gaierror):
                pass
    return False


def _validate_ip(ip_str: Optional[str]) -> Optional[str]:
    if not ip_str:
        return None
    cleaned = ip_str.strip()
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        return None


def get_client_ip(request: Request) -> str:
    """Extract client IP address securely.

    Does NOT trust client-supplied headers (X-Forwarded-For, X-Real-IP)
    unless the immediate peer connection originates from a configured trusted proxy.
    """
    settings = get_settings()
    peer_ip = request.client.host if request.client else "127.0.0.1"

    if is_trusted_proxy(peer_ip, settings.trusted_proxies):
        # 1. Check X-Real-IP (set by Nginx from $remote_addr)
        x_real_ip = _validate_ip(request.headers.get("x-real-ip"))
        if x_real_ip:
            return x_real_ip

        # 2. Check X-Forwarded-For (walk backwards skipping trusted proxies to find edge client)
        xff = request.headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            for candidate in reversed(parts):
                validated = _validate_ip(candidate)
                if validated and not is_trusted_proxy(validated, settings.trusted_proxies):
                    return validated
            for candidate in parts:
                validated = _validate_ip(candidate)
                if validated:
                    return validated

    return peer_ip


async def check_rate_limit(
    key: str,
    limit: int,
    window_seconds: int = 60,
    action_name: str = "requests",
) -> None:
    """Evaluate sliding-window rate limit and raise HTTP 429 if exceeded."""
    allowed, retry_after = await limiter.check(key, limit, window_seconds)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {action_name}. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
