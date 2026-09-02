"""Security regression coverage for authorized, bounded Sarvam TTS."""

from __future__ import annotations

import asyncio
import base64
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.auth import create_access_token, hash_password, limiter
from backend.config import get_settings
from backend.database import Base, get_db
from backend.main import app
from backend.models import AuditLog, ChatMessage, Incident, InvestigationSession, User
from backend.services.sarvam_tts import SarvamTTSError, TTSClip


TEST_SECRET = "test-secret-key-32-chars-long-secure-value!"
NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def tts_env(monkeypatch):
    limiter.reset()
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_SECRET)
    monkeypatch.setenv("SARVAM_TTS_ENABLED", "true")
    monkeypatch.setenv("SARVAM_API_KEY", "audit-safe-provider-key")
    monkeypatch.setenv("RATE_LIMIT_TTS_PER_MINUTE", "2")
    monkeypatch.setenv("MAX_CONCURRENT_TTS_PER_PROCESS", "1")
    monkeypatch.setenv("MAX_CONCURRENT_TTS_PER_USER", "1")
    monkeypatch.setenv("SARVAM_TTS_MAX_CHARACTERS", "100")
    monkeypatch.setenv("SARVAM_TTS_MAX_CHUNKS", "1")
    monkeypatch.setenv("SARVAM_TTS_MAX_AUDIO_BYTES_PER_CLIP", "100")
    monkeypatch.setenv("SARVAM_TTS_MAX_TOTAL_AUDIO_BYTES", "100")
    get_settings.cache_clear()

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    analyst_a_id, analyst_b_id, incident_id, session_id = [uuid.uuid4() for _ in range(4)]
    assistant_message_id, user_message_id = uuid.uuid4(), uuid.uuid4()
    analyst_a = User(id=analyst_a_id, email="a@soc.test", password_hash=hash_password("Password123!"), role="analyst", is_active=True)
    analyst_b = User(id=analyst_b_id, email="b@soc.test", password_hash=hash_password("Password123!"), role="analyst", is_active=True)
    incident = Incident(id=incident_id, title="TTS test", attack_type="BRUTE_FORCE", severity="HIGH", confidence=0.9, status="OPEN", first_seen=NOW, last_seen=NOW, event_count=1)
    session = InvestigationSession(id=session_id, incident_id=incident_id, analyst_id=analyst_a_id)
    assistant = ChatMessage(id=assistant_message_id, session_id=session_id, role="assistant", content="**Safe answer** [EV-001]", timestamp=NOW)
    user_message = ChatMessage(id=user_message_id, session_id=session_id, role="user", content="Sensitive user prompt", timestamp=NOW)
    async with session_factory() as db:
        db.add_all([analyst_a, analyst_b, incident, session, assistant, user_message])
        await db.commit()

    async def override_db():
        async with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield {
            "client": client,
            "session_factory": session_factory,
            "assistant_message_id": assistant_message_id,
            "user_message_id": user_message_id,
            "token_a": create_access_token(analyst_a_id, analyst_a.email, analyst_a.role, secret_key=TEST_SECRET),
            "token_b": create_access_token(analyst_b_id, analyst_b.email, analyst_b.role, secret_key=TEST_SECRET),
            "analyst_a_id": analyst_a_id,
        }
    finally:
        app.dependency_overrides.clear()
        limiter.reset()
        await engine.dispose()
        get_settings.cache_clear()


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestTTSSecurity:
    def test_unauthenticated_and_cross_user_requests_are_rejected(self, tts_env):
        client = tts_env["client"]
        message_id = tts_env["assistant_message_id"]
        assert client.post(f"/api/messages/{message_id}/tts").status_code == 401
        assert client.post(f"/api/messages/{message_id}/tts", headers=_headers(tts_env["token_b"])).status_code == 403

    def test_not_found_and_user_message_are_handled_safely(self, tts_env):
        client = tts_env["client"]
        headers = _headers(tts_env["token_a"])
        assert client.post(f"/api/messages/{uuid.uuid4()}/tts", headers=headers).status_code == 404
        response = client.post(f"/api/messages/{tts_env['user_message_id']}/tts", headers=headers)
        assert response.status_code == 400
        assert "assistant messages" in response.json()["detail"]

    def test_assistant_message_succeeds_without_mutating_content_and_audits_safely(self, tts_env):
        client = tts_env["client"]
        message_id = tts_env["assistant_message_id"]
        with patch("backend.main.synthesize", new_callable=AsyncMock, return_value=[TTSClip(b"wav", 0)]):
            response = client.post(f"/api/messages/{message_id}/tts", headers=_headers(tts_env["token_a"]))
        assert response.status_code == 200
        assert response.json()["audio_clips_base64"] == [base64.b64encode(b"wav").decode("ascii")]
        assert response.headers["cache-control"].startswith("no-store")

        async def verify():
            async with tts_env["session_factory"]() as db:
                message = (await db.execute(select(ChatMessage).where(ChatMessage.id == message_id))).scalar_one()
                audit = (await db.execute(select(AuditLog).where(AuditLog.entity_id == str(message_id)).order_by(AuditLog.timestamp.desc()))).scalars().first()
                return message, audit

        message, audit = asyncio.run(verify())
        assert message.content == "**Safe answer** [EV-001]"
        assert audit is not None and audit.status == "SUCCESS"
        serialized_audit = str(audit.details)
        assert message.content not in serialized_audit
        assert "audit-safe-provider-key" not in serialized_audit

    def test_disabled_and_missing_key_fail_with_generic_message(self, tts_env, monkeypatch):
        client = tts_env["client"]
        path = f"/api/messages/{tts_env['assistant_message_id']}/tts"
        monkeypatch.setenv("SARVAM_TTS_ENABLED", "false")
        get_settings.cache_clear()
        disabled = client.post(path, headers=_headers(tts_env["token_a"]))
        assert disabled.status_code == 503 and disabled.json()["detail"] == "Audio is temporarily unavailable."

        monkeypatch.setenv("SARVAM_TTS_ENABLED", "true")
        monkeypatch.delenv("SARVAM_API_KEY")
        get_settings.cache_clear()
        missing_key = client.post(path, headers=_headers(tts_env["token_a"]))
        assert missing_key.status_code == 503 and missing_key.json()["detail"] == "Audio is temporarily unavailable."

    def test_provider_failure_rate_and_concurrency_limits_are_generic(self, tts_env):
        client = tts_env["client"]
        path = f"/api/messages/{tts_env['assistant_message_id']}/tts"
        headers = _headers(tts_env["token_a"])
        with patch("backend.main.synthesize", new_callable=AsyncMock, side_effect=SarvamTTSError("provider-secret=leak-me")):
            response = client.post(path, headers=headers)
        assert response.status_code == 503
        assert response.json()["detail"] == "Audio is temporarily unavailable."
        assert "provider-secret" not in response.text

        async def provider_failure_audit():
            async with tts_env["session_factory"]() as db:
                return (await db.execute(
                    select(AuditLog)
                    .where(AuditLog.entity_id == str(tts_env["assistant_message_id"]))
                    .order_by(AuditLog.timestamp.desc())
                )).scalars().first()

        audit = asyncio.run(provider_failure_audit())
        assert audit is not None
        assert "provider-secret" not in str(audit.details)

        limiter.reset()
        asyncio.run(limiter.acquire_concurrency("tts_active:process", 1))
        with patch("backend.main.synthesize", new_callable=AsyncMock, return_value=[TTSClip(b"wav", 0)]):
            concurrent = client.post(path, headers=headers)
        asyncio.run(limiter.release_concurrency("tts_active:process"))
        assert concurrent.status_code == 429

        limiter.reset()
        asyncio.run(limiter.acquire_concurrency(f"tts_active:{tts_env['analyst_a_id']}", 1))
        with patch("backend.main.synthesize", new_callable=AsyncMock, return_value=[TTSClip(b"wav", 0)]):
            concurrent = client.post(path, headers=headers)
        asyncio.run(limiter.release_concurrency(f"tts_active:{tts_env['analyst_a_id']}"))
        assert concurrent.status_code == 429

        limiter.reset()
        with patch("backend.main.synthesize", new_callable=AsyncMock, return_value=[TTSClip(b"wav", 0)]):
            assert client.post(path, headers=headers).status_code == 200
            assert client.post(path, headers=headers).status_code == 200
            assert client.post(path, headers=headers).status_code == 429

    def test_maximum_text_limit_is_rejected_before_provider_call(self, tts_env):
        async def enlarge_message():
            async with tts_env["session_factory"]() as db:
                message = (await db.execute(select(ChatMessage).where(ChatMessage.id == tts_env["assistant_message_id"]))).scalar_one()
                message.content = "x" * 10_001
                await db.commit()

        asyncio.run(enlarge_message())
        with patch("backend.services.sarvam_tts._request_clip", new_callable=AsyncMock) as provider_request:
            response = tts_env["client"].post(
                f"/api/messages/{tts_env['assistant_message_id']}/tts",
                headers=_headers(tts_env["token_a"]),
            )
        assert response.status_code == 413
        provider_request.assert_not_awaited()

    def test_long_message_is_converted_to_briefing_rather_than_rejected(self, tts_env):
        async def set_long_message():
            async with tts_env["session_factory"]() as db:
                message = (await db.execute(select(ChatMessage).where(ChatMessage.id == tts_env["assistant_message_id"]))).scalar_one()
                message.content = (
                    "## Summary\n"
                    "An attacker operating from IP 10.10.5.200 targeted the account sarah.miller "
                    "on workstation-42.corp.local with a password guessing attack [EV-001]. "
                    "Following eight consecutive authentication failures [EV-001]–[EV-008], the attacker "
                    "successfully logged in at 14:15:51 UTC [EV-009]. Immediate containment actions "
                    "are necessary to isolate the host.\n\n"
                    "## Timeline\n" + "- 14:15:00 Event failure [EV-001]\n" * 40
                )
                await db.commit()

        asyncio.run(set_long_message())
        with patch("backend.services.sarvam_tts._request_clip", new_callable=AsyncMock, return_value=b"RIFF" + b"\x00" * 40) as mock_req:
            response = tts_env["client"].post(
                f"/api/messages/{tts_env['assistant_message_id']}/tts",
                headers=_headers(tts_env["token_a"]),
            )
        assert response.status_code == 200
        mock_req.assert_awaited()
        spoken_texts = [call.kwargs["text"] for call in mock_req.call_args_list]
        combined_spoken = " ".join(spoken_texts)
        assert "An attacker operating from IP 10.10.5.200" in combined_spoken
        assert "Event failure" not in combined_spoken
        assert "Full details and evidence remain in the console." in combined_spoken

