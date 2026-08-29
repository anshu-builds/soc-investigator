"""Unit tests for the Wazuh webhook API endpoint.

These tests use FastAPI's TestClient to simulate HTTP requests.
No running Wazuh Manager or database is required — the pipeline call
is mocked to isolate endpoint logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from fastapi.testclient import TestClient

from tests.fixtures.wazuh_alerts import (
    brute_force_scenario,
    ssh_auth_failure,
    ssh_auth_success,
)


# ---------------------------------------------------------------------------
# Test client setup
# ---------------------------------------------------------------------------

# Patch settings before importing the app to ensure consistent config
@pytest.fixture(autouse=True)
def _patch_settings(monkeypatch):
    """Set WAZUH_WEBHOOK_SECRET for test isolation."""
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "test-secret-42")

    # Clear settings cache so new env vars take effect
    from backend.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client():
    """FastAPI TestClient with mocked database dependency."""
    from backend.main import app, _dedup_cache
    from backend.database import get_db

    # Clear dedup cache between tests
    _dedup_cache.clear()

    async def _mock_db():
        mock = AsyncMock()
        mock.commit = AsyncMock()
        mock.rollback = AsyncMock()
        mock.flush = AsyncMock()
        mock.add = lambda x: None
        yield mock

    app.dependency_overrides[get_db] = _mock_db
    with patch("backend.main.create_all_tables", new_callable=AsyncMock):
        with TestClient(app) as c:
            yield c
    app.dependency_overrides.clear()


VALID_PAYLOAD = {"alerts": [ssh_auth_failure()]}
HEADERS = {"X-Wazuh-Token": "test-secret-42"}


# ---------------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------------


class TestWazuhAuth:
    def test_valid_token_accepted(self, client):
        with patch("backend.main.run_pipeline", new_callable=AsyncMock, return_value=(1, 0, 0)):
            resp = client.post(
                "/api/integrations/wazuh/alerts",
                json=VALID_PAYLOAD,
                headers=HEADERS,
            )
        assert resp.status_code == 200

    def test_missing_token_rejected(self, client):
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json=VALID_PAYLOAD,
        )
        assert resp.status_code == 401

    def test_wrong_token_rejected(self, client):
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json=VALID_PAYLOAD,
            headers={"X-Wazuh-Token": "wrong-secret"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Payload validation tests
# ---------------------------------------------------------------------------


class TestWazuhValidation:
    def test_invalid_json_returns_422(self, client):
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            content=b"not json",
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_missing_alerts_key_returns_422(self, client):
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json={"events": []},
            headers=HEADERS,
        )
        assert resp.status_code == 422

    def test_empty_alerts_returns_422(self, client):
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json={"alerts": []},
            headers=HEADERS,
        )
        assert resp.status_code == 422

    def test_alert_missing_rule_returns_422(self, client):
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json={"alerts": [{"timestamp": "2025-01-01T00:00:00+00:00", "agent": {"id": "1", "name": "h"}}]},
            headers=HEADERS,
        )
        assert resp.status_code == 422


    def test_malformed_content_length_returns_400(self, client):
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json=VALID_PAYLOAD,
            headers={**HEADERS, "Content-Length": "not-an-integer"},
        )
        assert resp.status_code == 400
        assert "Content-Length" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Deduplication & Retry tests
# ---------------------------------------------------------------------------


class TestWazuhDedup:
    def test_duplicate_alert_not_reprocessed(self, client):
        with patch("backend.main.run_pipeline", new_callable=AsyncMock, return_value=(1, 0, 0)) as mock_pipeline:
            # First request
            resp1 = client.post(
                "/api/integrations/wazuh/alerts",
                json=VALID_PAYLOAD,
                headers=HEADERS,
            )
            assert resp1.status_code == 200
            assert resp1.json()["processed"] == 1

            # Same alert again
            resp2 = client.post(
                "/api/integrations/wazuh/alerts",
                json=VALID_PAYLOAD,
                headers=HEADERS,
            )
            assert resp2.status_code == 200
            assert resp2.json()["duplicates"] == 1
            assert resp2.json()["processed"] == 0

            # Pipeline only called once
            assert mock_pipeline.call_count == 1

    def test_failed_processing_can_be_retried(self, client):
        """If run_pipeline or DB fails, the alert is not marked as duplicate and can be retried."""
        with patch("backend.main.run_pipeline", new_callable=AsyncMock, side_effect=RuntimeError("DB write failed")) as mock_pipeline:
            resp1 = client.post(
                "/api/integrations/wazuh/alerts",
                json=VALID_PAYLOAD,
                headers=HEADERS,
            )
            assert resp1.status_code == 500

        # Subsequent retry after issue resolves succeeds and is NOT treated as duplicate
        with patch("backend.main.run_pipeline", new_callable=AsyncMock, return_value=(1, 0, 0)) as mock_pipeline_retry:
            resp2 = client.post(
                "/api/integrations/wazuh/alerts",
                json=VALID_PAYLOAD,
                headers=HEADERS,
            )
            assert resp2.status_code == 200
            assert resp2.json()["processed"] == 1
            assert resp2.json()["duplicates"] == 0
            assert mock_pipeline_retry.call_count == 1


# ---------------------------------------------------------------------------
# Successful & Error processing tests
# ---------------------------------------------------------------------------


class TestWazuhProcessing:
    def test_batch_processing(self, client):
        alerts = brute_force_scenario(count=3)
        with patch("backend.main.run_pipeline", new_callable=AsyncMock, return_value=(3, 0, 0)):
            resp = client.post(
                "/api/integrations/wazuh/alerts",
                json={"alerts": alerts},
                headers=HEADERS,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["received"] == 3
        assert data["processed"] == 3
        assert data["duplicates"] == 0

    def test_response_structure(self, client):
        with patch("backend.main.run_pipeline", new_callable=AsyncMock, return_value=(1, 1, 1)):
            resp = client.post(
                "/api/integrations/wazuh/alerts",
                json=VALID_PAYLOAD,
                headers=HEADERS,
            )
        data = resp.json()
        assert "received" in data
        assert "processed" in data
        assert "duplicates" in data
        assert "errors" in data

    def test_pipeline_error_returns_generic_500_without_exposing_exception(self, client):
        """Internal stack traces or exception strings must not leak to caller."""
        with patch("backend.main.run_pipeline", new_callable=AsyncMock, side_effect=ValueError("Sensitive database schema details")):
            resp = client.post(
                "/api/integrations/wazuh/alerts",
                json=VALID_PAYLOAD,
                headers=HEADERS,
            )
        assert resp.status_code == 500
        detail = resp.json()["detail"]
        assert "Sensitive database schema details" not in detail
        assert detail == "Internal error processing security alerts"


# ---------------------------------------------------------------------------
# Status endpoint tests
# ---------------------------------------------------------------------------


class TestWazuhStatus:
    def test_status_endpoint(self, client):
        resp = client.get("/api/integrations/wazuh/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert data["authentication"] == "configured"
