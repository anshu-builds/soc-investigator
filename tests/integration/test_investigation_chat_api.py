"""Integration tests for the investigation chat API and multi-turn memory."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.database import Base, get_db
from backend.main import app
from backend.models import ChatMessage, Evidence, Incident, InvestigationSession, SecurityEvent

NOW = datetime(2025, 8, 19, 14, 20, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def seeded_app_client():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    # Seed incident, session, and events
    incident_id = uuid.uuid4()
    session_id = uuid.uuid4()
    event_id = uuid.uuid4()
    ev_id = uuid.uuid4()

    async with session_factory() as session:
        ev_obj = SecurityEvent(
            id=event_id,
            source_ip="192.168.1.100",
            username="admin",
            hostname="server-01",
            event_type="AUTH_FAILURE",
            event_category="authentication",
            timestamp=NOW,
            raw_log="Failed password for admin",
        )
        inc_obj = Incident(
            id=incident_id,
            title="Brute Force against admin",
            attack_type="BRUTE_FORCE",
            severity="HIGH",
            confidence=0.9,
            status="OPEN",
            affected_username="admin",
            source_ip="192.168.1.100",
            first_seen=NOW,
            last_seen=NOW,
            event_count=1,
        )
        evidence_obj = Evidence(
            id=ev_id,
            incident_id=incident_id,
            event_id=event_id,
            role="INITIAL_ACCESS",
            sequence_order=1,
        )
        inv_session = InvestigationSession(
            id=session_id,
            incident_id=incident_id,
        )

        session.add_all([ev_obj, inc_obj, evidence_obj, inv_session])
        await session.commit()

    async def _override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _override_get_db

    with patch("backend.main.create_all_tables", new_callable=AsyncMock):
        with TestClient(app) as test_client:
            yield test_client, session_id, incident_id, ev_id

    app.dependency_overrides.clear()
    await engine.dispose()


class TestInvestigationChatAPI:
    def test_first_turn_and_second_turn_chat(self, seeded_app_client):
        client, session_id, incident_id, ev_id = seeded_app_client

        mock_llm_t1 = (
            "## Summary\n"
            "An attacker tried to brute force the admin account [EV-001].\n\n"
            "## Evidence\n"
            "- [EV-001] Failed password for admin\n\n"
            "## Recommended Actions\n"
            "1. Block 192.168.1.100."
        )
        mock_llm_t2 = (
            "## Summary\n"
            "Following up on the previous question, the source IP is 192.168.1.100 [EV-001].\n\n"
            "## Recommended Actions\n"
            "1. Apply firewall block."
        )

        with patch("ai.investigation_chain.call_llm", new_callable=AsyncMock) as mock_llm:
            # Turn 1: First question
            mock_llm.return_value = mock_llm_t1
            resp1 = client.post(
                f"/api/sessions/{session_id}/chat",
                json={"message": "What is the attack summary?"},
            )
            assert resp1.status_code == 200
            data1 = resp1.json()
            assert str(ev_id) in data1["evidence_ids"]
            assert "brute force the admin account" in data1["answer"]

            # Verify Turn 1 had no previous conversation history
            t1_sys_prompt = mock_llm.call_args[0][0]
            assert "No previous conversation history." in t1_sys_prompt

            # Turn 2: Follow-up question
            mock_llm.return_value = mock_llm_t2
            resp2 = client.post(
                f"/api/sessions/{session_id}/chat",
                json={"message": "What IP should we block?"},
            )
            assert resp2.status_code == 200
            data2 = resp2.json()
            assert str(ev_id) in data2["evidence_ids"]

            # Verify Turn 2 received Turn 1 in system prompt conversation history
            t2_sys_prompt = mock_llm.call_args[0][0]
            assert "Analyst: What is the attack summary?" in t2_sys_prompt
            assert "Assistant: ## Summary" in t2_sys_prompt

    def test_chat_session_not_found(self, seeded_app_client):
        client, _, _, _ = seeded_app_client
        non_existent_id = uuid.uuid4()
        resp = client.post(
            f"/api/sessions/{non_existent_id}/chat",
            json={"message": "Hello?"},
        )
        assert resp.status_code == 404
        assert "Session not found" in resp.json()["detail"]

    def test_chat_history_bounded_to_recent_ten(self, seeded_app_client):
        client, session_id, _, _ = seeded_app_client

        with patch("ai.investigation_chain.call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = "## Summary\nTurn response."

            # Perform 12 chat turns
            for i in range(1, 13):
                resp = client.post(
                    f"/api/sessions/{session_id}/chat",
                    json={"message": f"Question number {i}"},
                )
                assert resp.status_code == 200

            # On turn 12, check prompt history
            last_prompt = mock_llm.call_args[0][0]
            # Turn 1 and 2 user messages should have fallen out of the 10-message window
            assert "Question number 1\n" not in last_prompt
            assert "Question number 2\n" not in last_prompt
            # Recent turns (e.g. 11) should definitely be present
            assert "Question number 11" in last_prompt
