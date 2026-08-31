"""Tests for AI-generated incident summaries in report service and API endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.database import Base, get_db
from backend.main import app
from backend.models import Evidence, Incident, Report, SecurityEvent

NOW = datetime(2025, 8, 19, 14, 20, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def seeded_report_env():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    incident_id = uuid.uuid4()
    event_id = uuid.uuid4()
    ev_id = uuid.uuid4()

    async with session_factory() as session:
        event = SecurityEvent(
            id=event_id,
            source_ip="192.168.1.50",
            username="analyst_user",
            hostname="workstation-01",
            event_type="AUTH_FAILURE",
            event_category="authentication",
            timestamp=NOW,
            raw_log="Failed SSH password for analyst_user",
        )
        incident = Incident(
            id=incident_id,
            title="Brute Force against analyst_user",
            attack_type="BRUTE_FORCE",
            severity="HIGH",
            confidence=0.88,
            status="OPEN",
            affected_username="analyst_user",
            source_ip="192.168.1.50",
            first_seen=NOW,
            last_seen=NOW,
            event_count=1,
            attack_hypothesis={"narrative": "Observed brute force attempt."},
        )
        evidence = Evidence(
            id=ev_id,
            incident_id=incident_id,
            event_id=event_id,
            role="INITIAL_ACCESS",
            sequence_order=1,
        )
        session.add_all([event, incident, evidence])
        await session.commit()

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app, raise_server_exceptions=True)

    try:
        yield client, incident_id
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()


@pytest.mark.asyncio
async def test_create_report_with_ai_summary_wires_rag_retriever(seeded_report_env):
    client, incident_id = seeded_report_env

    mock_summary_text = (
        "Executive AI Summary: An unauthorized brute force attack was detected "
        "targeting analyst_user from source IP 192.168.1.50 [EV-001]."
    )

    with patch("backend.main.generate_incident_summary", new_callable=AsyncMock) as mock_gen_summary, \
         patch("rag.retriever.get_retriever") as mock_get_retriever:

        mock_mock_retriever = AsyncMock()
        mock_get_retriever.return_value = mock_mock_retriever
        mock_gen_summary.return_value = mock_summary_text

        resp = client.post(
            f"/api/incidents/{incident_id}/report",
            json={"format": "MARKDOWN", "include_ai_summary": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        report_id = data["report_id"]
        assert "download_url" in data

        # Verify that get_retriever was called and passed to generate_incident_summary
        mock_get_retriever.assert_called_once()
        mock_gen_summary.assert_called_once()
        passed_retriever = mock_gen_summary.call_args.kwargs.get("rag_retriever")
        assert passed_retriever == mock_mock_retriever

        # Verify report record has ai_summary populated
        get_resp = client.get(f"/api/reports/{report_id}")
        assert get_resp.status_code == 200
        report_data = get_resp.json()
        assert report_data["ai_summary"] == mock_summary_text
        assert mock_summary_text in report_data["content"]

        # Verify download content includes the AI summary
        dl_resp = client.get(f"/api/reports/{report_id}/download")
        assert dl_resp.status_code == 200
        assert mock_summary_text in dl_resp.text


@pytest.mark.asyncio
async def test_create_report_without_ai_summary(seeded_report_env):
    client, incident_id = seeded_report_env

    with patch("backend.main.generate_incident_summary", new_callable=AsyncMock) as mock_gen_summary:
        resp = client.post(
            f"/api/incidents/{incident_id}/report",
            json={"format": "MARKDOWN", "include_ai_summary": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        report_id = data["report_id"]
        mock_gen_summary.assert_not_called()

        get_resp = client.get(f"/api/reports/{report_id}")
        assert get_resp.status_code == 200
        report_data = get_resp.json()
        assert report_data["ai_summary"] is None
        # Fallback to narrative in the content
        assert "Observed brute force attempt." in report_data["content"]


@pytest.mark.asyncio
async def test_create_report_ai_summary_failure_graceful_fallback(seeded_report_env):
    client, incident_id = seeded_report_env

    with patch("backend.main.generate_incident_summary", new_callable=AsyncMock) as mock_gen_summary:
        # LLM failure gracefully returns None
        mock_gen_summary.return_value = None

        resp = client.post(
            f"/api/incidents/{incident_id}/report",
            json={"format": "MARKDOWN", "include_ai_summary": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        report_id = data["report_id"]

        get_resp = client.get(f"/api/reports/{report_id}")
        assert get_resp.status_code == 200
        report_data = get_resp.json()
        assert report_data["ai_summary"] is None
        assert "Observed brute force attempt." in report_data["content"]
