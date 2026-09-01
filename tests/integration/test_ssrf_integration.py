"""Integration tests verifying SSRF, network boundary, authorization, and rate limiting controls."""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.database import get_db
from backend.main import app, _poll_lock, _dedup_cache
from backend.models import User
from backend.security import SSRFSecurityError, validate_url_ssrf
from rag.ingest.ingest_mitre import ingest_mitre


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "integration-test-secret-key-ssrf-sec04")
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "valid-wazuh-secret")
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh.test:55000")
    monkeypatch.setenv("WAZUH_API_USERNAME", "wazuh_admin")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "wazuh_secret_pass")
    from backend.config import get_settings
    get_settings.cache_clear()
    _dedup_cache.clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def admin_user():
    return User(
        id=uuid.uuid4(),
        email="admin@soc.local",
        password_hash="fakehash",
        role="admin",
        is_active=True,
    )


@pytest.fixture
def analyst_user():
    return User(
        id=uuid.uuid4(),
        email="analyst@soc.local",
        password_hash="fakehash",
        role="analyst",
        is_active=True,
    )


@pytest.fixture
def test_client():
    async def _mock_db():
        mock = AsyncMock()
        mock.commit = AsyncMock()
        mock.rollback = AsyncMock()
        yield mock

    app.dependency_overrides[get_db] = _mock_db
    with patch("backend.main.create_all_tables", new_callable=AsyncMock), \
         patch("backend.main.ensure_seed_admin", new_callable=AsyncMock):
        with TestClient(app) as client:
            yield client
    app.dependency_overrides.clear()


class TestWazuhPollingAuthorizationAndLimits:
    """Verify admin-only authorization, rate limiting, and concurrency control for Wazuh polling."""

    def test_wazuh_poll_forbidden_for_analyst(self, clean_env, analyst_user, test_client):
        from backend.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: analyst_user

        resp = test_client.post("/api/integrations/wazuh/poll")
        assert resp.status_code == 403
        assert "Administrative privileges required" in resp.json()["detail"]

        app.dependency_overrides.pop(get_current_user, None)

    def test_wazuh_poll_allowed_for_admin(self, clean_env, admin_user, test_client):
        from backend.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: admin_user

        mock_poll_response = AsyncMock(
            return_value=MagicMock(
                fetched=5,
                processed=5,
                duplicates=0,
                watermark="2026-09-01T00:00:00Z",
                errors=[],
            )
        )

        with patch("backend.main._wazuh_poller") as mock_poller:
            mock_poller.poll_once = mock_poll_response
            resp = test_client.post("/api/integrations/wazuh/poll")
            assert resp.status_code == 200
            assert resp.json()["fetched"] == 5

        app.dependency_overrides.pop(get_current_user, None)

    def test_wazuh_poll_concurrency_lock(self, clean_env, admin_user, test_client):
        from backend.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: admin_user

        # Acquire lock to simulate another poll in progress
        async def acquire():
            await _poll_lock.acquire()
        asyncio.run(acquire())

        try:
            resp = test_client.post("/api/integrations/wazuh/poll")
            assert resp.status_code == 409
            assert "operation is already in progress" in resp.json()["detail"]
        finally:
            _poll_lock.release()

        app.dependency_overrides.pop(get_current_user, None)

    def test_wazuh_poll_rate_limit(self, clean_env, admin_user, test_client):
        from backend.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: admin_user

        mock_poll_response = AsyncMock(
            return_value=MagicMock(
                fetched=0,
                processed=0,
                duplicates=0,
                watermark=None,
                errors=[],
            )
        )

        with patch("backend.main._wazuh_poller") as mock_poller:
            mock_poller.poll_once = mock_poll_response
            # Limit is 3 per minute
            for i in range(3):
                r = test_client.post("/api/integrations/wazuh/poll")
                assert r.status_code == 200

            # 4th request must be rate-limited
            blocked = test_client.post("/api/integrations/wazuh/poll")
            assert blocked.status_code == 429
            assert "Rate limit exceeded" in blocked.json()["detail"]

        app.dependency_overrides.pop(get_current_user, None)


class TestMitreIngestionSecurity:
    """Test SSRF validation in MITRE ATT&CK STIX ingestion."""

    def test_mitre_ingest_rejects_malicious_url(self, monkeypatch):
        monkeypatch.setattr("rag.ingest.ingest_mitre.MITRE_URL", "http://169.254.169.254/latest")
        with pytest.raises(RuntimeError, match="rejected by SSRF security policy"):
            ingest_mitre()

    def test_mitre_ingest_rejects_file_scheme(self, monkeypatch):
        monkeypatch.setattr("rag.ingest.ingest_mitre.MITRE_URL", "file:///etc/passwd")
        with pytest.raises(RuntimeError, match="rejected by SSRF security policy"):
            ingest_mitre()
