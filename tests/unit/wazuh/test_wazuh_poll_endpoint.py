"""Tests for Wazuh manual poll and extended status endpoints."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.models import User
from tests.fixtures.wazuh_alerts import ssh_auth_failure


@pytest.fixture(autouse=True)
def _patch_settings(monkeypatch):
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "test-secret-42")
    monkeypatch.setenv("WAZUH_API_ENABLED", "true")
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh.test:55000")
    monkeypatch.setenv("WAZUH_API_USERNAME", "test-user")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "test-pass")

    from backend.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client():
    import backend.main as main_mod
    from backend.main import app, _dedup_cache
    from backend.database import get_db

    _dedup_cache.clear()
    main_mod._wazuh_poller = None

    async def _mock_db():
        mock = AsyncMock()
        mock.commit = AsyncMock()
        mock.rollback = AsyncMock()
        mock.flush = AsyncMock()
    admin_user = User(
        id=uuid.uuid4(),
        email="admin@wazuh.test",
        password_hash="fakehash",
        role="admin",
        is_active=True,
    )

    async def _mock_admin():
        return admin_user

    async def _mock_user():
        return admin_user

    from backend.auth import get_current_user, require_admin
    app.dependency_overrides[get_db] = _mock_db
    app.dependency_overrides[get_current_user] = _mock_user
    app.dependency_overrides[require_admin] = _mock_admin
    with patch("backend.main.create_all_tables", new_callable=AsyncMock), \
         patch("backend.main.ensure_seed_admin", new_callable=AsyncMock):
        with TestClient(app) as c:
            yield c
    app.dependency_overrides.clear()
    main_mod._wazuh_poller = None


class TestWazuhPollEndpoint:
    def test_manual_poll_success(self, client):
        mock_poller = AsyncMock()
        from backend.services.wazuh_poller import WazuhPollResponse
        mock_poller.poll_once.return_value = WazuhPollResponse(
            fetched=5,
            processed=4,
            duplicates=1,
            watermark="2025-06-15T14:30:00+00:00",
            errors=[],
        )

        with patch("backend.main._wazuh_poller", mock_poller):
            resp = client.post("/api/integrations/wazuh/poll")
            assert resp.status_code == 200
            data = resp.json()
            assert data["fetched"] == 5
            assert data["processed"] == 4
            assert data["duplicates"] == 1
            assert data["watermark"] == "2025-06-15T14:30:00+00:00"

    def test_manual_poll_unconfigured_returns_400(self, client, monkeypatch):
        monkeypatch.setenv("WAZUH_API_URL", "")
        monkeypatch.setenv("WAZUH_API_USERNAME", "")
        monkeypatch.setenv("WAZUH_API_PASSWORD", "")
        from backend.config import get_settings
        get_settings.cache_clear()

        resp = client.post("/api/integrations/wazuh/poll")
        assert resp.status_code == 400
        assert "not configured" in resp.json()["detail"].lower()

    def test_manual_poll_upstream_failure_sanitizes_error_detail(self, client):
        mock_poller = AsyncMock()
        sensitive_msg = "Upstream connection refused to postgresql://secret:password@internal-db:5432"
        mock_poller.poll_once.side_effect = RuntimeError(sensitive_msg)

        with patch("backend.main._wazuh_poller", mock_poller):
            resp = client.post("/api/integrations/wazuh/poll")
            assert resp.status_code == 502
            # Verify exact sanitized error message returned
            assert resp.json()["detail"] == "Wazuh polling failed. Check server logs for details."
            # Verify internal exception details are NEVER disclosed
            assert sensitive_msg not in resp.text
            assert "internal-db" not in resp.text
            assert "password" not in resp.text

    def test_startup_does_not_block_on_wazuh_unavailability(self, monkeypatch):
        """Verify that backend startup succeeds even if Wazuh poller cannot connect initially."""
        monkeypatch.setenv("WAZUH_API_ENABLED", "true")
        monkeypatch.setenv("WAZUH_API_URL", "https://unreachable.wazuh.local:55000")
        monkeypatch.setenv("WAZUH_API_USERNAME", "user")
        monkeypatch.setenv("WAZUH_API_PASSWORD", "pass")
        from backend.config import get_settings
        get_settings.cache_clear()

        from backend.main import app
        with patch("backend.main.create_all_tables", new_callable=AsyncMock):
            with TestClient(app) as test_client:
                # Health check and app should be fully operational
                health = test_client.get("/health")
                assert health.status_code == 200
                assert health.json()["status"] == "ok"


class TestWazuhStatusEndpointExtended:
    def test_status_endpoint_structure(self, client):
        resp = client.get("/api/integrations/wazuh/status")
        assert resp.status_code == 200
        data = resp.json()

        # Check Phase 1 backward compatibility
        assert data["status"] == "ready"
        assert data["authentication"] == "configured"
        assert isinstance(data["dedup_cache_size"], int)

        # Check Phase 2 API polling diagnostics
        assert "api_polling" in data
        polling = data["api_polling"]
        assert polling["enabled"] is True
        assert polling["configured"] is True
        assert polling["api_url"] == "https://wazuh.test:55000"
        assert polling["running"] is False  # not started in mock test
        assert "total_alerts_fetched" in polling
        assert "total_alerts_processed" in polling
        assert "watermark" in polling
        # Ensure passwords and tokens are NOT exposed
        assert "password" not in str(data)
        assert "token" not in str(data)
