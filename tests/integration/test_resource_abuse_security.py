"""Integration tests for SEC-02: Rate limiting, resource protection, and LLM concurrency controls."""

from __future__ import annotations

import asyncio
import io
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai.llm_client import (
    call_llm,
    get_llm_semaphore,
    reset_llm_semaphore,
)
from backend.auth import create_access_token, hash_password, limiter
from backend.config import get_settings
from backend.database import Base, get_db
from backend.main import app
from backend.models import (
    Evidence,
    Incident,
    InvestigationSession,
    SecurityEvent,
    User,
)

NOW = datetime(2025, 8, 19, 14, 20, 0, tzinfo=timezone.utc)
TEST_SECRET = "test-secret-key-32-chars-long-secure-value!"


@pytest_asyncio.fixture(autouse=True)
def _reset_limiter():
    limiter.reset()
    reset_llm_semaphore()
    yield
    limiter.reset()
    reset_llm_semaphore()


@pytest_asyncio.fixture
async def resource_security_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_SECRET)
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "test-wazuh-secret")
    monkeypatch.setenv("ENVIRONMENT", "development")
    # Set tight limits for test predictability
    monkeypatch.setenv("RATE_LIMIT_LOGIN_PER_MINUTE", "5")
    monkeypatch.setenv("RATE_LIMIT_NLU_PER_MINUTE", "5")
    monkeypatch.setenv("RATE_LIMIT_CHAT_PER_MINUTE", "5")
    monkeypatch.setenv("RATE_LIMIT_REPORT_PER_MINUTE", "3")
    monkeypatch.setenv("RATE_LIMIT_LOG_UPLOAD_PER_MINUTE", "4")
    monkeypatch.setenv("RATE_LIMIT_WAZUH_POLL_PER_MINUTE", "2")
    monkeypatch.setenv("MAX_CONCURRENT_LLM_REQUESTS", "2")
    monkeypatch.setenv("MAX_CONCURRENT_LLM_PER_USER", "2")
    monkeypatch.setenv("MAX_CONCURRENT_REPORTS", "1")
    get_settings.cache_clear()

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    user_a_id = uuid.uuid4()
    user_b_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    session_a_id = uuid.uuid4()

    user_a = User(
        id=user_a_id,
        email="analyst.a@soc.corp",
        password_hash=hash_password("Password123!"),
        role="analyst",
        is_active=True,
    )
    user_b = User(
        id=user_b_id,
        email="analyst.b@soc.corp",
        password_hash=hash_password("Password123!"),
        role="analyst",
        is_active=True,
    )
    admin_user = User(
        id=admin_id,
        email="admin@soc.corp",
        password_hash=hash_password("AdminPass123!"),
        role="admin",
        is_active=True,
    )
    incident = Incident(
        id=incident_id,
        title="Test Abuse Incident",
        attack_type="BRUTE_FORCE",
        severity="HIGH",
        confidence=0.9,
        status="OPEN",
        first_seen=NOW,
        last_seen=NOW,
        event_count=1,
    )
    session_a = InvestigationSession(
        id=session_a_id,
        incident_id=incident_id,
        analyst_id=user_a_id,
    )

    async with session_factory() as session:
        session.add_all([user_a, user_b, admin_user, incident, session_a])
        await session.commit()

    async def _override_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _override_db

    token_a = create_access_token(user_a_id, user_a.email, user_a.role, secret_key=TEST_SECRET)
    token_b = create_access_token(user_b_id, user_b.email, user_b.role, secret_key=TEST_SECRET)
    token_admin = create_access_token(admin_id, admin_user.email, admin_user.role, secret_key=TEST_SECRET)

    client = TestClient(app, raise_server_exceptions=False)

    try:
        yield {
            "client": client,
            "user_a_id": user_a_id,
            "user_b_id": user_b_id,
            "admin_id": admin_id,
            "incident_id": incident_id,
            "session_a_id": session_a_id,
            "token_a": token_a,
            "token_b": token_b,
            "token_admin": token_admin,
        }
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()
        get_settings.cache_clear()


class TestLoginBruteForceProtection:
    def test_repeated_failed_logins_throttled_with_429(self, resource_security_env):
        client = resource_security_env["client"]

        # 5 attempts allowed by rate limit
        for _ in range(5):
            resp = client.post("/api/auth/login", json={
                "email": "analyst.a@soc.corp",
                "password": "WrongPassword123!",
            })
            assert resp.status_code == 401
            assert resp.json()["detail"] == "Invalid email or password"

        # 6th attempt is throttled
        resp = client.post("/api/auth/login", json={
            "email": "analyst.a@soc.corp",
            "password": "WrongPassword123!",
        })
        assert resp.status_code == 429
        assert "Rate limit exceeded" in resp.json()["detail"]
        assert "Retry-After" in resp.headers

    def test_spoofed_x_forwarded_for_cannot_bypass_login_rate_limit(self, resource_security_env):
        client = resource_security_env["client"]

        # Send 5 attempts with different spoofed X-Forwarded-For headers
        for i in range(5):
            resp = client.post(
                "/api/auth/login",
                json={"email": "analyst.a@soc.corp", "password": "WrongPassword!"},
                headers={"X-Forwarded-For": f"198.51.100.{i + 1}"},
            )
            assert resp.status_code == 401

        # 6th attempt with yet another spoofed IP must STILL be rate limited
        resp = client.post(
            "/api/auth/login",
            json={"email": "analyst.a@soc.corp", "password": "WrongPassword!"},
            headers={"X-Forwarded-For": "198.51.100.99"},
        )
        assert resp.status_code == 429


class TestNLUQueryRateLimiting:
    def test_nlu_rate_limit_per_user(self, resource_security_env):
        client = resource_security_env["client"]
        token_a = resource_security_env["token_a"]
        token_b = resource_security_env["token_b"]

        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        # User A makes 5 allowed requests
        for _ in range(5):
            resp = client.post("/api/nlu/query", json={"question": "show me incidents"}, headers=headers_a)
            assert resp.status_code == 200

        # User A 6th request is throttled
        resp = client.post("/api/nlu/query", json={"question": "show me incidents"}, headers=headers_a)
        assert resp.status_code == 429
        assert "Rate limit exceeded" in resp.json()["detail"]

        # User B should still be allowed
        resp_b = client.post("/api/nlu/query", json={"question": "show me incidents"}, headers=headers_b)
        assert resp_b.status_code == 200


class TestChatRateLimitingAndConcurrency:
    def test_chat_rate_limiting(self, resource_security_env):
        client = resource_security_env["client"]
        token_a = resource_security_env["token_a"]
        session_a_id = resource_security_env["session_a_id"]
        headers = {"Authorization": f"Bearer {token_a}"}

        with patch("backend.main.run_investigation_chain", new_callable=AsyncMock) as mock_chain:
            mock_chain.return_value = {
                "answer": "Test response",
                "evidence_ids": [],
                "mitre_references": [],
                "rag_sources": [],
                "answer_type": "DETERMINED",
                "confidence": 0.95,
            }

            for _ in range(5):
                resp = client.post(
                    f"/api/sessions/{session_a_id}/chat",
                    json={"message": "What is the status?"},
                    headers=headers,
                )
                assert resp.status_code == 200

            # 6th request is throttled
            resp = client.post(
                f"/api/sessions/{session_a_id}/chat",
                json={"message": "What is the status?"},
                headers=headers,
            )
            assert resp.status_code == 429
            assert "Rate limit exceeded" in resp.json()["detail"]


class TestReportRateLimitingAndConcurrency:
    def test_report_generation_rate_limited(self, resource_security_env):
        client = resource_security_env["client"]
        token_a = resource_security_env["token_a"]
        incident_id = resource_security_env["incident_id"]
        headers = {"Authorization": f"Bearer {token_a}"}

        with patch("backend.main.generate_report", new_callable=AsyncMock) as mock_gen:
            mock_report = MagicMock()
            mock_report.id = uuid.uuid4()
            mock_gen.return_value = mock_report

            # Limit is 3 per minute
            for _ in range(3):
                resp = client.post(
                    f"/api/incidents/{incident_id}/report",
                    json={"format": "MARKDOWN", "include_ai_summary": False},
                    headers=headers,
                )
                assert resp.status_code == 200

            # 4th request exceeds rate limit
            resp = client.post(
                f"/api/incidents/{incident_id}/report",
                json={"format": "MARKDOWN", "include_ai_summary": False},
                headers=headers,
            )
            assert resp.status_code == 429
            assert "Rate limit exceeded" in resp.json()["detail"]


class TestWazuhPollRateLimiting:
    def test_wazuh_poll_rate_limited(self, resource_security_env):
        client = resource_security_env["client"]
        token_admin = resource_security_env["token_admin"]
        headers = {"Authorization": f"Bearer {token_admin}"}

        from backend.services.wazuh_poller import WazuhPollResponse
        mock_poller = AsyncMock()
        mock_poller.poll_once.return_value = WazuhPollResponse(
            fetched=0, processed=0, duplicates=0, watermark=None, errors=[]
        )

        with patch("backend.main._wazuh_poller", mock_poller):
            # Limit is 2 per minute
            for _ in range(2):
                resp = client.post("/api/integrations/wazuh/poll", headers=headers)
                assert resp.status_code == 200

            # 3rd poll is rate limited
            resp = client.post("/api/integrations/wazuh/poll", headers=headers)
            assert resp.status_code == 429
            assert "Rate limit exceeded" in resp.json()["detail"]


class TestUploadAbuseProtection:
    def test_upload_rate_limited(self, resource_security_env):
        client = resource_security_env["client"]
        token_a = resource_security_env["token_a"]
        headers = {"Authorization": f"Bearer {token_a}"}

        csv_data = "timestamp,source_ip,username,hostname,event_type,event_category,raw_log\n"

        with patch("backend.main.run_pipeline", new_callable=AsyncMock) as mock_pipe:
            mock_pipe.return_value = (0, 0, 0)

            # Limit is 4 per minute
            for _ in range(4):
                files = {"file": ("logs.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")}
                resp = client.post("/api/logs/upload", files=files, headers=headers)
                assert resp.status_code == 200

            # 5th upload is rate limited
            files = {"file": ("logs.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")}
            resp = client.post("/api/logs/upload", files=files, headers=headers)
            assert resp.status_code == 429

    def test_oversized_upload_rejected_by_chunk_guard(self, resource_security_env):
        client = resource_security_env["client"]
        token_a = resource_security_env["token_a"]
        headers = {"Authorization": f"Bearer {token_a}"}

        # 11 MB payload
        oversized_data = b"x" * (11 * 1024 * 1024)
        files = {"file": ("huge_logs.csv", io.BytesIO(oversized_data), "text/csv")}

        resp = client.post("/api/logs/upload", files=files, headers=headers)
        assert resp.status_code == 413
        assert "exceeds 10MB limit" in resp.json()["detail"]


class TestLLMGlobalConcurrencySemaphore:
    @pytest.mark.asyncio
    async def test_llm_concurrency_bounded_and_released_on_success(self, monkeypatch):
        monkeypatch.setenv("MAX_CONCURRENT_LLM_REQUESTS", "2")
        get_settings.cache_clear()
        reset_llm_semaphore()

        sem = get_llm_semaphore()
        assert sem._value == 2

        active_count = 0
        max_active = 0

        async def _mock_generate(*args, **kwargs):
            nonlocal active_count, max_active
            active_count += 1
            if active_count > max_active:
                max_active = active_count
            await asyncio.sleep(0.05)
            active_count -= 1
            return "ok"

        from ai.llm_client import GeminiAdapter
        with patch.object(GeminiAdapter, "generate", side_effect=_mock_generate):
            # Launch 6 parallel calls
            tasks = [call_llm("sys", f"user {i}") for i in range(6)]
            results = await asyncio.gather(*tasks)

        assert all(r == "ok" for r in results)
        assert max_active <= 2  # Concurrency never exceeded 2
        assert sem._value == 2  # Fully released

    @pytest.mark.asyncio
    async def test_llm_concurrency_released_on_exception(self, monkeypatch):
        monkeypatch.setenv("MAX_CONCURRENT_LLM_REQUESTS", "1")
        monkeypatch.setenv("LLM_PROVIDER", "gemini")
        get_settings.cache_clear()
        reset_llm_semaphore()

        sem = get_llm_semaphore()
        assert sem._value == 1

        from ai.llm_client import GeminiAdapter, OpenAIAdapter
        with patch.object(GeminiAdapter, "generate", side_effect=ValueError("Gemini auth error")):
            with patch.object(OpenAIAdapter, "generate", side_effect=ValueError("OpenAI auth error")):
                with pytest.raises(ValueError, match="OpenAI auth error"):
                    await call_llm("sys", "user")

        # Semaphore MUST be released despite the exception
        assert sem._value == 1
