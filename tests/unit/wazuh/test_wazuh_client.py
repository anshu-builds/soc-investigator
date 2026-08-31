"""Unit tests for WazuhClient REST API client."""

from __future__ import annotations

from datetime import datetime, timezone
import httpx
import pytest

from backend.services.wazuh_client import WazuhClient, WazuhAuthError, WazuhAPIError
from tests.fixtures.wazuh_alerts import ssh_auth_failure


class TestWazuhClientAuth:
    @pytest.mark.asyncio
    async def test_auth_success(self):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/security/user/authenticate"
            assert request.headers.get("Authorization") is not None or request.headers.get("authorization") is not None
            return httpx.Response(200, json={"data": {"token": "test-jwt-token-12345"}})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wazuh-user",
                password="wazuh-password",
                client=mock_http,
            )
            token = await client.authenticate()
            assert token == "test-jwt-token-12345"
            assert client._token == "test-jwt-token-12345"

    @pytest.mark.asyncio
    async def test_auth_missing_credentials(self):
        client = WazuhClient(base_url="", username="", password="")
        with pytest.raises(WazuhAuthError, match="not configured"):
            await client.authenticate()

    @pytest.mark.asyncio
    async def test_auth_failure_401(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": 1, "message": "Invalid user or password"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wrong-user",
                password="wrong-password",
                client=mock_http,
            )
            with pytest.raises(WazuhAuthError, match="HTTP 401"):
                await client.authenticate()

    @pytest.mark.asyncio
    async def test_auth_server_error_500(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wazuh-user",
                password="wazuh-password",
                client=mock_http,
            )
            with pytest.raises(WazuhAPIError, match="HTTP 500"):
                await client.authenticate()


class TestWazuhClientRequests:
    @pytest.mark.asyncio
    async def test_token_reuse_for_multiple_requests(self):
        auth_calls = 0
        api_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal auth_calls, api_calls
            if request.url.path == "/security/user/authenticate":
                auth_calls += 1
                return httpx.Response(200, json={"data": {"token": "jwt-token-fixed"}})
            if request.url.path == "/alerts":
                api_calls += 1
                assert request.headers.get("authorization") == "Bearer jwt-token-fixed"
                return httpx.Response(200, json={"data": {"affected_items": [ssh_auth_failure()], "total_affected_items": 1}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wazuh-user",
                password="wazuh-password",
                client=mock_http,
            )
            alerts1, total1 = await client.fetch_alerts()
            alerts2, total2 = await client.fetch_alerts()

            assert len(alerts1) == 1
            assert len(alerts2) == 1
            assert auth_calls == 1  # Authenticated once, token reused
            assert api_calls == 2

    @pytest.mark.asyncio
    async def test_auto_refresh_token_on_401(self):
        auth_calls = 0
        api_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal auth_calls, api_calls
            if request.url.path == "/security/user/authenticate":
                auth_calls += 1
                return httpx.Response(200, json={"data": {"token": f"jwt-token-v{auth_calls}"}})
            if request.url.path == "/alerts":
                api_calls += 1
                if request.headers.get("authorization") == "Bearer jwt-token-v1":
                    # Simulate token expiration
                    return httpx.Response(401, json={"error": 1, "message": "Token expired"})
                if request.headers.get("authorization") == "Bearer jwt-token-v2":
                    return httpx.Response(200, json={"data": {"affected_items": [ssh_auth_failure()], "total_affected_items": 1}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wazuh-user",
                password="wazuh-password",
                client=mock_http,
            )
            alerts, total = await client.fetch_alerts()
            assert len(alerts) == 1
            assert auth_calls == 2  # Re-authenticated
            assert api_calls == 2   # Retried after 401

    @pytest.mark.asyncio
    async def test_transient_retry_on_500(self):
        api_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal api_calls
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(200, json={"data": {"token": "jwt-token-retry"}})
            if request.url.path == "/alerts":
                api_calls += 1
                if api_calls < 2:
                    return httpx.Response(502, text="Bad Gateway")
                return httpx.Response(200, json={"data": {"affected_items": [ssh_auth_failure()], "total_affected_items": 1}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wazuh-user",
                password="wazuh-password",
                max_retries=3,
                client=mock_http,
            )
            alerts, total = await client.fetch_alerts()
            assert len(alerts) == 1
            assert api_calls == 2

    @pytest.mark.asyncio
    async def test_fetch_alerts_query_params(self):
        last_params = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal last_params
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(200, json={"data": {"token": "jwt-token-param"}})
            if request.url.path == "/alerts":
                last_params = dict(request.url.params)
                return httpx.Response(200, json={"data": {"affected_items": [], "total_affected_items": 0}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wazuh-user",
                password="wazuh-password",
                client=mock_http,
            )
            t_start = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
            t_end = datetime(2025, 6, 15, 13, 0, 0, tzinfo=timezone.utc)
            await client.fetch_alerts(time_start=t_start, time_end=t_end, limit=100, offset=20)

            assert last_params.get("limit") == "100"
            assert last_params.get("offset") == "20"
            assert "timestamp>2025-06-15T12:00:00+00:00" in last_params.get("q", "")
            assert "timestamp<=2025-06-15T13:00:00+00:00" in last_params.get("q", "")

    @pytest.mark.asyncio
    async def test_request_timeout(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(200, json={"data": {"token": "jwt-token-timeout"}})
            raise httpx.ReadTimeout("Request timed out")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wazuh-user",
                password="wazuh-password",
                max_retries=2,
                client=mock_http,
            )
            with pytest.raises(WazuhAPIError, match="timed out"):
                await client.fetch_alerts()

    @pytest.mark.asyncio
    async def test_fetch_alerts_empty_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(200, json={"data": {"token": "jwt-token-empty"}})
            if request.url.path == "/alerts":
                return httpx.Response(200, json={"data": {"affected_items": [], "total_affected_items": 0}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as mock_http:
            client = WazuhClient(
                base_url="https://wazuh.local:55000",
                username="wazuh-user",
                password="wazuh-password",
                client=mock_http,
            )
            alerts, total = await client.fetch_alerts()
            assert alerts == []
            assert total == 0
