"""Comprehensive adversarial test suite for SSRF, network boundary isolation, and external integrations.

Covers:
- Localhost and loopback addresses (IPv4, IPv6, mapped, compatible)
- RFC1918 private subnets and CG-NAT
- Cloud metadata endpoints (AWS, GCP, Azure, Alibaba)
- Link-local, multicast, unspecified, and broadcast addresses
- Alternative IP notations (decimal integer, octal, hex, BSD shorthand)
- URL scheme whitelisting and parser confusion
- Embedded userinfo / credentials
- SafeAsyncClient redirect inspection and blocking of internal targets
- Oversized response body handling
- Wazuh URL validation and endpoint path-traversal prevention
- Inbound webhook Content-Type and chunked body size protection
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from backend.security import (
    SSRFResolutionError,
    SSRFSecurityError,
    SafeAsyncClient,
    is_ip_allowed,
    read_bounded_response,
    validate_url_ssrf,
)
from backend.services.wazuh_client import WazuhAPIError, WazuhClient


class TestIPAddressValidation:
    """Rigorous IP address policy testing against evasion techniques."""

    def test_localhost_ipv4_blocked(self):
        for ip_str in ["127.0.0.1", "127.0.0.2", "127.10.20.30", "127.255.255.254"]:
            ip = ipaddress.ip_address(ip_str)
            allowed, reason = is_ip_allowed(ip, allow_loopback=False)
            assert not allowed
            assert "Loopback" in reason

    def test_localhost_ipv6_blocked(self):
        ip = ipaddress.ip_address("::1")
        allowed, reason = is_ip_allowed(ip, allow_loopback=False)
        assert not allowed
        assert "Loopback" in reason

    def test_ipv4_mapped_ipv6_loopback_blocked(self):
        ip = ipaddress.ip_address("::ffff:127.0.0.1")
        allowed, reason = is_ip_allowed(ip, allow_loopback=False)
        assert not allowed
        assert "Loopback" in reason or "127.0.0.1" in reason

    def test_ipv4_compatible_ipv6_loopback_blocked(self):
        ip = ipaddress.ip_address("::127.0.0.1")
        allowed, reason = is_ip_allowed(ip, allow_loopback=False)
        assert not allowed

    def test_6to4_loopback_blocked(self):
        ip = ipaddress.ip_address("2002:7f00:0001::")
        allowed, reason = is_ip_allowed(ip, allow_loopback=False)
        assert not allowed

    def test_rfc1918_private_ips_blocked(self):
        for ip_str in [
            "10.0.0.1", "10.254.254.254",
            "172.16.0.1", "172.24.0.1", "172.31.255.254",
            "192.168.0.1", "192.168.100.50",
        ]:
            ip = ipaddress.ip_address(ip_str)
            allowed, reason = is_ip_allowed(ip, allow_private=False)
            assert not allowed
            assert "Private network" in reason

    def test_link_local_blocked(self):
        for ip_str in ["169.254.1.1", "169.254.100.100", "fe80::1", "fe80::dead:beef"]:
            ip = ipaddress.ip_address(ip_str)
            allowed, reason = is_ip_allowed(ip, allow_private=False)
            assert not allowed

    def test_cloud_metadata_blocked_always(self):
        for ip_str in [
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "fd00:ec2::254",
            "100.100.100.200",
        ]:
            ip = ipaddress.ip_address(ip_str)
            # Must remain blocked even if allow_private or allow_loopback is enabled
            allowed, reason = is_ip_allowed(ip, allow_private=True, allow_loopback=True)
            assert not allowed
            assert "Cloud metadata" in reason or "Link-local" in reason

    def test_multicast_blocked(self):
        for ip_str in ["224.0.0.1", "239.255.255.250", "ff02::1"]:
            ip = ipaddress.ip_address(ip_str)
            allowed, reason = is_ip_allowed(ip)
            assert not allowed

    def test_unspecified_and_broadcast_blocked(self):
        for ip_str in ["0.0.0.0", "::", "255.255.255.255"]:
            ip = ipaddress.ip_address(ip_str)
            allowed, reason = is_ip_allowed(ip)
            assert not allowed

    def test_carrier_grade_nat_blocked(self):
        ip = ipaddress.ip_address("100.64.0.1")
        allowed, reason = is_ip_allowed(ip, allow_private=False)
        assert not allowed

    def test_documentation_and_benchmark_blocked(self):
        for ip_str in ["192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1"]:
            ip = ipaddress.ip_address(ip_str)
            allowed, reason = is_ip_allowed(ip)
            assert not allowed

    def test_ipv6_unique_local_blocked(self):
        for ip_str in ["fc00::1", "fd12:3456:789a::1"]:
            ip = ipaddress.ip_address(ip_str)
            allowed, reason = is_ip_allowed(ip, allow_private=False)
            assert not allowed

    def test_public_ips_allowed(self):
        for ip_str in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]:
            ip = ipaddress.ip_address(ip_str)
            allowed, reason = is_ip_allowed(ip, allow_private=False)
            assert allowed
            assert reason == "OK"


class TestURLParsingAndSchemes:
    """Test URL parsing, scheme restrictions, and userinfo evasion."""

    def test_empty_or_non_string_rejected(self):
        for val in ["", None, "   "]:
            with pytest.raises(SSRFSecurityError, match="non-empty string"):
                validate_url_ssrf(val)

    def test_invalid_schemes_rejected(self):
        disallowed = [
            "ftp://example.com/file",
            "file:///etc/passwd",
            "gopher://127.0.0.1:70/",
            "dict://127.0.0.1:2628/",
            "ldap://localhost:389/",
            "data:text/plain;base64,SGVsbG8=",
            "javascript:alert(1)",
        ]
        for url in disallowed:
            with pytest.raises(SSRFSecurityError, match="Disallowed URL scheme|Missing URL scheme"):
                validate_url_ssrf(url)

    def test_missing_scheme_rejected(self):
        with pytest.raises(SSRFSecurityError, match="Missing URL scheme"):
            validate_url_ssrf("example.com/api")

    def test_embedded_credentials_rejected(self):
        userinfo_urls = [
            "http://user:password@example.com/",
            "https://admin@example.com/dashboard",
            "http://google.com@127.0.0.1/",
            "https://user:pass@169.254.169.254/latest",
        ]
        for url in userinfo_urls:
            with pytest.raises(SSRFSecurityError, match="Embedded credentials|Embedded userinfo"):
                validate_url_ssrf(url)

    def test_control_characters_rejected(self):
        for url in [
            "http://example.com/\x00admin",
            "http://example.com/\r\nHost: evil.com",
            "http://example.com/\x1b[31m",
        ]:
            with pytest.raises(SSRFSecurityError, match="illegal whitespace or control"):
                validate_url_ssrf(url)

    def test_invalid_ports_rejected(self):
        for port in [0, 65536, -1, 100000]:
            with pytest.raises(SSRFSecurityError, match="Invalid port number"):
                validate_url_ssrf(f"http://example.com:{port}")

    def test_localhost_aliases_rejected(self):
        for host in ["localhost", "localhost.", "ip6-localhost", "localhost.localdomain"]:
            with pytest.raises(SSRFSecurityError, match="Localhost alias"):
                validate_url_ssrf(f"http://{host}:8000/", allow_loopback=False)


class TestAlternativeIPRepresentations:
    """Test defense against alternative IP encodings (decimal integer, hex, octal, shorthand)."""

    def test_decimal_integer_loopback_rejected(self):
        # 2130706433 is 127.0.0.1
        with pytest.raises(SSRFSecurityError, match="Loopback|blocked"):
            validate_url_ssrf("http://2130706433/", allow_loopback=False)

    def test_decimal_integer_metadata_rejected(self):
        # 2852039166 is 169.254.169.254
        with pytest.raises(SSRFSecurityError, match="Cloud metadata|blocked"):
            validate_url_ssrf("http://2852039166/", allow_private=True, allow_loopback=True)

    def test_hex_ip_loopback_rejected(self):
        # 0x7f000001 is 127.0.0.1
        with pytest.raises(SSRFSecurityError, match="Loopback|blocked"):
            validate_url_ssrf("http://0x7f000001/", allow_loopback=False)

    def test_hex_ip_metadata_rejected(self):
        # 0xa9fea9fe is 169.254.169.254
        with pytest.raises(SSRFSecurityError, match="Cloud metadata|blocked"):
            validate_url_ssrf("http://0xa9fea9fe/", allow_private=True, allow_loopback=True)

    def test_octal_ip_loopback_rejected(self):
        # 0177.0.0.1 is 127.0.0.1
        with pytest.raises(SSRFSecurityError, match="Loopback|blocked"):
            validate_url_ssrf("http://0177.0.0.1/", allow_loopback=False)

    def test_bsd_shorthand_loopback_rejected(self):
        # 127.1 is 127.0.0.1
        with pytest.raises(SSRFSecurityError, match="Loopback|blocked"):
            validate_url_ssrf("http://127.1/", allow_loopback=False)

    def test_bsd_shorthand_zero_rejected(self):
        # 0 is 0.0.0.0
        with pytest.raises(SSRFSecurityError, match="Unspecified|blocked"):
            validate_url_ssrf("http://0/", allow_loopback=False)


class TestDNSResolutionAndRebinding:
    """Test DNS resolution inspection and multi-record validation."""

    def test_dns_resolves_to_private_ip_rejected(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 80))
            ]
            with pytest.raises(SSRFSecurityError, match="Private network"):
                validate_url_ssrf("http://internal-corp-service.com/", allow_private=False)

    def test_dns_resolves_to_cloud_metadata_rejected(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))
            ]
            with pytest.raises(SSRFSecurityError, match="Cloud metadata"):
                validate_url_ssrf("http://metadata.attacker.com/", allow_private=True, allow_loopback=True)

    def test_dns_multi_ip_with_one_private_rejected(self):
        with patch("socket.getaddrinfo") as mock_gai:
            # One public IP, one loopback IP
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
            ]
            with pytest.raises(SSRFSecurityError, match="Loopback"):
                validate_url_ssrf("http://dual-homed-rebinder.com/", allow_loopback=False)

    def test_dns_failure_raises_resolution_error(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            with pytest.raises(SSRFResolutionError):
                validate_url_ssrf("http://nonexistent-domain-xyz123.com/", allow_private=False)


class TestSafeAsyncClientAndRedirects:
    """Test SafeAsyncClient enforcement of SSRF validation and redirect interception."""

    @pytest.mark.asyncio
    async def test_direct_localhost_request_blocked(self):
        client = SafeAsyncClient(allow_loopback=False)
        try:
            with pytest.raises(SSRFSecurityError, match="Loopback|Localhost"):
                await client.get("http://127.0.0.1:8000/api")
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_direct_metadata_request_blocked(self):
        client = SafeAsyncClient(allow_private=True, allow_loopback=True)
        try:
            with pytest.raises(SSRFSecurityError, match="Cloud metadata"):
                await client.get("http://169.254.169.254/latest/meta-data/")
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_redirect_to_localhost_blocked(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "public.test":
                return httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/admin"})
            return httpx.Response(200, text="OK")

        transport = httpx.MockTransport(handler)
        client = SafeAsyncClient(transport=transport, allow_private=True, allow_loopback=False)
        try:
            with pytest.raises(SSRFSecurityError, match="Loopback"):
                await client.get("http://public.test/start")
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_redirect_to_cloud_metadata_blocked(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "public.test":
                return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
            return httpx.Response(200, text="OK")

        transport = httpx.MockTransport(handler)
        client = SafeAsyncClient(transport=transport, allow_private=True, allow_loopback=True)
        try:
            with pytest.raises(SSRFSecurityError, match="Cloud metadata"):
                await client.get("http://public.test/start")
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_redirect_to_private_rfc1918_blocked(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "public.test":
                return httpx.Response(302, headers={"Location": "http://10.0.1.50/internal"})
            return httpx.Response(200, text="OK")

        transport = httpx.MockTransport(handler)
        client = SafeAsyncClient(transport=transport, allow_private=False)
        try:
            with pytest.raises(SSRFSecurityError, match="Private network"):
                await client.get("http://public.test/start")
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_exceeding_max_redirects_raises_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://public.test/loop"})

        transport = httpx.MockTransport(handler)
        client = SafeAsyncClient(transport=transport, allow_private=True, max_redirects=2)
        try:
            with pytest.raises(SSRFSecurityError, match="Too many redirects"):
                await client.get("http://public.test/start")
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_oversized_response_rejected(self):
        resp = httpx.Response(
            200,
            headers={"Content-Length": "20000000"},  # 20 MB
            content=b"A" * 1000,
        )
        with pytest.raises(SSRFSecurityError, match="exceeds maximum limit"):
            await read_bounded_response(resp, max_bytes=1024 * 1024)

    @pytest.mark.asyncio
    async def test_oversized_streaming_response_rejected(self):
        async def fake_stream(*args, **kwargs):
            for _ in range(20):
                yield b"X" * (64 * 1024)

        resp = httpx.Response(200, content=b"")
        resp.aiter_bytes = fake_stream  # type: ignore

        with pytest.raises(SSRFSecurityError, match="exceeded maximum allowed limit"):
            await read_bounded_response(resp, max_bytes=512 * 1024)


class TestWazuhSecurityControls:
    """Test security controls specific to Wazuh API client and endpoint."""

    def test_wazuh_client_rejects_cloud_metadata(self):
        with pytest.raises(WazuhAPIError, match="rejected by SSRF"):
            WazuhClient(
                base_url="http://169.254.169.254",
                username="admin",
                password="password",
            )

    def test_wazuh_client_rejects_invalid_scheme(self):
        with pytest.raises(WazuhAPIError, match="rejected by SSRF"):
            WazuhClient(
                base_url="ftp://wazuh.corp:55000",
                username="admin",
                password="password",
            )

    def test_wazuh_client_rejects_embedded_credentials(self):
        with pytest.raises(WazuhAPIError, match="rejected by SSRF"):
            WazuhClient(
                base_url="https://admin:secret@wazuh.corp:55000",
                username="admin",
                password="password",
            )

    @pytest.mark.asyncio
    async def test_wazuh_client_endpoint_traversal_rejected(self):
        mock_http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        client = WazuhClient(
            base_url="https://wazuh.test:55000",
            username="admin",
            password="password",
            client=mock_http,
        )
        client._token = "valid-token"

        try:
            with pytest.raises(WazuhAPIError, match="Path traversal sequences"):
                await client.request("GET", "/alerts/../../etc/passwd")

            with pytest.raises(WazuhAPIError, match="Path traversal sequences"):
                await client.request("GET", "../admin")
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_wazuh_client_endpoint_absolute_url_rejected(self):
        mock_http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        client = WazuhClient(
            base_url="https://wazuh.test:55000",
            username="admin",
            password="password",
            client=mock_http,
        )
        client._token = "valid-token"

        try:
            with pytest.raises(WazuhAPIError, match="Absolute URLs and protocol schemes"):
                await client.request("GET", "https://attacker.com/leak")

            with pytest.raises(WazuhAPIError, match="Absolute URLs and protocol schemes"):
                await client.request("GET", "//attacker.com/leak")
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_wazuh_client_oversized_response_rejected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            # Send 15 MB response
            return httpx.Response(200, headers={"Content-Length": str(15 * 1024 * 1024)}, content=b"{}")

        mock_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = WazuhClient(
            base_url="https://wazuh.test:55000",
            username="admin",
            password="password",
            client=mock_http,
        )
        client._token = "valid-token"

        try:
            with pytest.raises(WazuhAPIError, match="rejected by security policy|exceeds maximum"):
                await client.request("GET", "/alerts")
        finally:
            await client.close()


class TestWebhookSecurityControls:
    """Test security controls on the inbound Wazuh webhook endpoint."""

    @pytest.fixture
    def webhook_client(self, monkeypatch):
        monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "super-secret-token")
        from backend.config import get_settings
        get_settings.cache_clear()

        from backend.main import app, _dedup_cache
        from backend.database import get_db
        from fastapi.testclient import TestClient

        _dedup_cache.clear()

        async def _mock_db():
            mock = AsyncMock()
            mock.commit = AsyncMock()
            mock.rollback = AsyncMock()
            yield mock

        app.dependency_overrides[get_db] = _mock_db
        with patch("backend.main.create_all_tables", new_callable=AsyncMock), \
             patch("backend.main.ensure_seed_admin", new_callable=AsyncMock):
            with TestClient(app) as c:
                yield c
        app.dependency_overrides.clear()
        get_settings.cache_clear()

    def test_webhook_unsupported_content_type_rejected(self, webhook_client):
        resp = webhook_client.post(
            "/api/integrations/wazuh/alerts",
            content=b"<xml></xml>",
            headers={"X-Wazuh-Token": "super-secret-token", "Content-Type": "application/xml"},
        )
        assert resp.status_code == 415
        assert "application/json" in resp.json()["detail"]

    def test_webhook_oversized_payload_via_content_length_rejected(self, webhook_client):
        resp = webhook_client.post(
            "/api/integrations/wazuh/alerts",
            content=b"{}",
            headers={
                "X-Wazuh-Token": "super-secret-token",
                "Content-Type": "application/json",
                "Content-Length": "2000000",  # 2 MB
            },
        )
        assert resp.status_code == 413

    def test_webhook_oversized_streaming_payload_rejected(self, webhook_client):
        # 1.5 MB of dummy data without valid Content-Length
        large_body = b"{" + b" " * (1_500_000) + b"}"
        resp = webhook_client.post(
            "/api/integrations/wazuh/alerts",
            content=large_body,
            headers={
                "X-Wazuh-Token": "super-secret-token",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 413

    def test_webhook_malformed_json_rejected(self, webhook_client):
        resp = webhook_client.post(
            "/api/integrations/wazuh/alerts",
            content=b'{"alerts": [incomplete json',
            headers={
                "X-Wazuh-Token": "super-secret-token",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 422
