"""Adversarial security integration tests for SEC-06.

Audits:
- BOLA / IDOR on unassigned investigation sessions
- Business logic & state transitions (closed/false-positive incidents)
- Resource exhaustion & rate limits (session creation & status update)
- Input validation bounds & CPU DoS prevention (LoginRequest)
- Mass assignment prevention (forbid extra fields across schemas)
- API consistency & error handling (404 on nonexistent evidence/reports)
- TOCTOU alert deduplication race condition in-flight tracking
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.auth import create_access_token
from backend.auth.limiter import limiter
from backend.database import Base, get_db
from backend.main import _dedup_in_flight, _is_duplicate, _record_dedup, _release_in_flight, app
from backend.models import Incident, InvestigationSession, SecurityEvent, User

TEST_SECRET = "test-sec06-jwt-adversarial-audit-secret-key-32chars"
NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def sec06_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_SECRET)
    from backend.config import get_settings
    get_settings.cache_clear()
    limiter.reset()
    _dedup_in_flight.clear()

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    analyst1_id = uuid.uuid4()
    analyst2_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    closed_incident_id = uuid.uuid4()
    session_analyst1_id = uuid.uuid4()
    unassigned_session_id = uuid.uuid4()

    async with session_factory() as session:
        u1 = User(id=analyst1_id, email="analyst1@soc.corp", password_hash="hash1", role="analyst", is_active=True)
        u2 = User(id=analyst2_id, email="analyst2@soc.corp", password_hash="hash2", role="analyst", is_active=True)
        admin = User(id=admin_id, email="admin@soc.corp", password_hash="hash3", role="admin", is_active=True)

        inc_open = Incident(
            id=incident_id,
            title="Open Incident Alpha",
            attack_type="BRUTE_FORCE",
            severity="HIGH",
            confidence=0.9,
            status="OPEN",
            first_seen=NOW,
            last_seen=NOW,
            event_count=5,
        )
        inc_closed = Incident(
            id=closed_incident_id,
            title="Closed Incident Beta",
            attack_type="ACCOUNT_COMPROMISE",
            severity="LOW",
            confidence=0.8,
            status="CLOSED",
            first_seen=NOW,
            last_seen=NOW,
            event_count=2,
        )

        sess1 = InvestigationSession(id=session_analyst1_id, incident_id=incident_id, analyst_id=analyst1_id)
        sess_unassigned = InvestigationSession(id=unassigned_session_id, incident_id=incident_id, analyst_id=None)

        session.add_all([u1, u2, admin, inc_open, inc_closed, sess1, sess_unassigned])
        await session.commit()

    async def override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    token_analyst1 = create_access_token(analyst1_id, "analyst1@soc.corp", "analyst", secret_key=TEST_SECRET)
    token_analyst2 = create_access_token(analyst2_id, "analyst2@soc.corp", "analyst", secret_key=TEST_SECRET)
    token_admin = create_access_token(admin_id, "admin@soc.corp", "admin", secret_key=TEST_SECRET)

    yield {
        "client": client,
        "token_analyst1": token_analyst1,
        "token_analyst2": token_analyst2,
        "token_admin": token_admin,
        "incident_id": incident_id,
        "closed_incident_id": closed_incident_id,
        "session_analyst1_id": session_analyst1_id,
        "unassigned_session_id": unassigned_session_id,
    }

    app.dependency_overrides.clear()
    limiter.reset()
    _dedup_in_flight.clear()


class TestInputValidationAndCpuDos:
    """Audit input validation bounds and CPU amplification protection."""

    def test_oversized_password_rejected_without_pbkdf2_exhaustion(self, sec06_env):
        client = sec06_env["client"]
        oversized_pass = "A" * 500  # Max permitted is 128
        resp = client.post("/api/auth/login", json={"email": "analyst1@soc.corp", "password": oversized_pass})
        assert resp.status_code == 422
        assert "password" in str(resp.json())

    def test_extra_fields_forbidden_on_login(self, sec06_env):
        client = sec06_env["client"]
        resp = client.post(
            "/api/auth/login",
            json={"email": "analyst1@soc.corp", "password": "validpassword", "role": "admin"},
        )
        assert resp.status_code == 422
        assert "extra_forbidden" in str(resp.json()).lower() or "extra fields not permitted" in str(resp.json()).lower()


class TestMassAssignmentDefense:
    """Verify unexpected fields are rejected across Pydantic models."""

    def test_incident_status_update_forbids_extra_fields(self, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        incident_id = sec06_env["incident_id"]

        resp = client.patch(
            f"/api/incidents/{incident_id}/status",
            headers=headers,
            json={"status": "INVESTIGATING", "role": "admin", "analyst_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 422

    def test_chat_request_forbids_extra_fields(self, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        session_id = sec06_env["session_analyst1_id"]

        resp = client.post(
            f"/api/sessions/{session_id}/chat",
            headers=headers,
            json={"message": "What happened?", "role": "assistant", "ai_confidence": 1.0},
        )
        assert resp.status_code == 422

    def test_report_request_forbids_extra_fields(self, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        incident_id = sec06_env["incident_id"]

        resp = client.post(
            f"/api/incidents/{incident_id}/report",
            headers=headers,
            json={"format": "MARKDOWN", "override_ai": True},
        )
        assert resp.status_code == 422

    def test_nl_query_forbids_extra_fields(self, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}

        resp = client.post(
            "/api/nlu/query",
            headers=headers,
            json={"question": "show me failed logins", "sql_injection": "'; DROP TABLE users; --"},
        )
        assert resp.status_code == 422


class TestBusinessLogicAndStateTransitions:
    """Audit business logic rules around closed incidents and sessions."""

    def test_cannot_create_session_for_closed_incident(self, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        closed_id = sec06_env["closed_incident_id"]

        resp = client.post(f"/api/incidents/{closed_id}/sessions", headers=headers)
        assert resp.status_code == 400
        assert "closed or false positive" in resp.json()["detail"].lower()

    @patch("backend.main.run_investigation_chain")
    def test_cannot_chat_in_session_of_closed_incident(self, mock_chain, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        incident_id = sec06_env["incident_id"]
        session_id = sec06_env["session_analyst1_id"]

        # Close the incident first
        patch_resp = client.patch(
            f"/api/incidents/{incident_id}/status",
            headers=headers,
            json={"status": "CLOSED"},
        )
        assert patch_resp.status_code == 200

        # Attempt to chat
        chat_resp = client.post(
            f"/api/sessions/{session_id}/chat",
            headers=headers,
            json={"message": "Any new activity?"},
        )
        assert chat_resp.status_code == 400
        assert "closed or false positive" in chat_resp.json()["detail"].lower()
        mock_chain.assert_not_called()


class TestBolaAndSessionOwnership:
    """Audit object-level authorization on investigation sessions."""

    def test_unassigned_session_denied_to_non_admin_analyst(self, sec06_env):
        client = sec06_env["client"]
        headers_analyst = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        unassigned_id = sec06_env["unassigned_session_id"]

        resp = client.get(f"/api/sessions/{unassigned_id}/messages", headers=headers_analyst)
        assert resp.status_code == 403
        assert "access denied" in resp.json()["detail"].lower()

    def test_unassigned_session_accessible_by_admin(self, sec06_env):
        client = sec06_env["client"]
        headers_admin = {"Authorization": f"Bearer {sec06_env['token_admin']}"}
        unassigned_id = sec06_env["unassigned_session_id"]

        resp = client.get(f"/api/sessions/{unassigned_id}/messages", headers=headers_admin)
        assert resp.status_code == 200
        assert resp.json()["messages"] == []


class TestApiConsistencyAndErrorHandling:
    """Audit 404 consistency for non-existent entities."""

    def test_nonexistent_incident_evidence_returns_404_not_200(self, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        dummy_id = uuid.uuid4()

        resp = client.get(f"/api/incidents/{dummy_id}/evidence", headers=headers)
        assert resp.status_code == 404
        assert "incident not found" in resp.json()["detail"].lower()

    def test_nonexistent_incident_report_returns_404_not_500(self, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        dummy_id = uuid.uuid4()

        resp = client.post(
            f"/api/incidents/{dummy_id}/report",
            headers=headers,
            json={"format": "MARKDOWN", "include_ai_summary": False},
        )
        assert resp.status_code == 404
        assert "incident not found" in resp.json()["detail"].lower()


class TestRateLimitingAndToctouRaces:
    """Audit rate limits and in-flight deduplication concurrency."""

    def test_session_creation_rate_limiting(self, sec06_env):
        client = sec06_env["client"]
        headers = {"Authorization": f"Bearer {sec06_env['token_analyst1']}"}
        incident_id = sec06_env["incident_id"]

        # 20 sessions allowed per minute
        for _ in range(20):
            r = client.post(f"/api/incidents/{incident_id}/sessions", headers=headers)
            assert r.status_code == 200

        # 21st attempt should be rate limited
        limited_resp = client.post(f"/api/incidents/{incident_id}/sessions", headers=headers)
        assert limited_resp.status_code == 429
        assert "Rate limit exceeded" in limited_resp.json()["detail"]

    def test_in_flight_deduplication_tracking(self):
        digest = "test_digest_12345"
        assert not _is_duplicate(digest)

        # Mark in flight
        _dedup_in_flight.add(digest)
        assert _is_duplicate(digest)

        # Commit digest
        _record_dedup([digest])
        assert _is_duplicate(digest)
        assert digest not in _dedup_in_flight

        # Test failure release
        digest2 = "test_digest_67890"
        _dedup_in_flight.add(digest2)
        assert _is_duplicate(digest2)
        _release_in_flight([digest2])
        assert not _is_duplicate(digest2)
