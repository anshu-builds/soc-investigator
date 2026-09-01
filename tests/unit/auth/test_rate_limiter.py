"""Unit tests for in-memory rate limiter, concurrency controls, and safe IP resolution."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from backend.auth.limiter import InMemoryRateLimiter, check_rate_limit, get_client_ip
from backend.config import get_settings


class TestInMemoryRateLimiter:
    @pytest.mark.asyncio
    async def test_requests_under_limit_allowed(self):
        limiter = InMemoryRateLimiter()
        for _ in range(5):
            allowed, retry_after = await limiter.check("user:1", limit=5, window_seconds=60)
            assert allowed is True
            assert retry_after == 0

    @pytest.mark.asyncio
    async def test_requests_exceeding_limit_rejected_with_retry_after(self):
        limiter = InMemoryRateLimiter()
        for _ in range(3):
            allowed, _ = await limiter.check("user:2", limit=3, window_seconds=60)
            assert allowed is True

        allowed, retry_after = await limiter.check("user:2", limit=3, window_seconds=60)
        assert allowed is False
        assert retry_after >= 1
        assert isinstance(retry_after, int)

    @pytest.mark.asyncio
    async def test_isolated_keys(self):
        limiter = InMemoryRateLimiter()
        # Max out user A
        for _ in range(3):
            await limiter.check("user:A", limit=3, window_seconds=60)

        assert (await limiter.check("user:A", limit=3, window_seconds=60))[0] is False
        # User B should still be allowed
        assert (await limiter.check("user:B", limit=3, window_seconds=60))[0] is True

    @pytest.mark.asyncio
    async def test_concurrency_acquisition_and_release(self):
        limiter = InMemoryRateLimiter()
        assert await limiter.acquire_concurrency("user:C", max_concurrent=2) is True
        assert await limiter.acquire_concurrency("user:C", max_concurrent=2) is True
        # Exceeds max 2
        assert await limiter.acquire_concurrency("user:C", max_concurrent=2) is False

        # Release one slot
        await limiter.release_concurrency("user:C")
        assert await limiter.acquire_concurrency("user:C", max_concurrent=2) is True

        # Clean up
        await limiter.release_concurrency("user:C")
        await limiter.release_concurrency("user:C")

    @pytest.mark.asyncio
    async def test_check_rate_limit_helper_raises_429(self):
        limiter = InMemoryRateLimiter()
        from unittest.mock import patch
        with patch("backend.auth.limiter.limiter", limiter):
            for _ in range(2):
                await check_rate_limit("test_action", limit=2, window_seconds=60, action_name="test actions")

            with pytest.raises(HTTPException) as exc_info:
                await check_rate_limit("test_action", limit=2, window_seconds=60, action_name="test actions")

            assert exc_info.value.status_code == 429
            assert "Rate limit exceeded" in exc_info.value.detail
            assert "Retry-After" in exc_info.value.headers


class TestClientIPResolution:
    def test_direct_connection_uses_peer_ip(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXIES", "")
        get_settings.cache_clear()

        request = MagicMock()
        request.client.host = "203.0.113.195"
        request.headers = {"x-forwarded-for": "10.0.0.1, 192.168.1.1"}

        # Untrusted proxy -> must ignore X-Forwarded-For
        assert get_client_ip(request) == "203.0.113.195"

    def test_trusted_proxy_parses_forwarded_ip(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXIES", "127.0.0.1, 10.0.0.100")
        get_settings.cache_clear()

        request = MagicMock()
        request.client.host = "10.0.0.100"  # Peer is trusted reverse proxy
        request.headers = {"x-forwarded-for": "203.0.113.50, 10.0.0.100"}

        assert get_client_ip(request) == "203.0.113.50"

    def test_missing_client_peer_defaults_safely(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXIES", "")
        get_settings.cache_clear()

        request = MagicMock()
        request.client = None
        assert get_client_ip(request) == "127.0.0.1"
