import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ai.summary_generator import generate_incident_summary

pytestmark = pytest.mark.asyncio


def _mock_incident_context():
    mock_incident = MagicMock()
    mock_incident.title = "Brute Force Attack on Admin"
    mock_incident.attack_type = "BRUTE_FORCE"
    return {
        "incident": mock_incident,
        "context_text": "INCIDENT: Brute Force Attack on Admin\n"
                        "- **22:00 UTC** User admin failed login from 10.1.2.3 [EV-001]\n"
                        "- **22:00:15 UTC** User admin successful login from 10.1.2.3 [EV-002]",
        "evidence_map": {"EV-001": "uuid-001", "EV-002": "uuid-002"},
        "techniques": [MagicMock(technique_id="T1110")],
    }


@patch("ai.summary_generator.call_llm", new_callable=AsyncMock)
@patch("ai.summary_generator.build_context", new_callable=AsyncMock)
async def test_generate_incident_summary_success(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_rag_retriever = AsyncMock()
    mock_rag_retriever.retrieve.return_value = [
        {"title": "Brute Force Playbook", "text": "Containment steps for brute force"}
    ]

    mock_call_llm.return_value = (
        "An automated brute force authentication attack was observed targeting the administrator account [EV-001]. "
        "The attacker subsequently achieved successful authentication [EV-002] from source IP 10.1.2.3."
    )

    summary = await generate_incident_summary(
        db=AsyncMock(),
        incident_id=uuid.uuid4(),
        rag_retriever=mock_rag_retriever,
    )

    assert summary is not None
    assert "brute force authentication attack" in summary
    assert "[EV-001]" in summary
    assert "[EV-002]" in summary

    # Verify system prompt has grounding rules and RAG knowledge
    sys_prompt = mock_call_llm.call_args[0][0]
    assert "EVIDENCE RULES — MUST FOLLOW:" in sys_prompt
    assert "Brute Force Playbook" in sys_prompt
    assert "10.1.2.3" in sys_prompt


@patch("ai.summary_generator.call_llm", new_callable=AsyncMock)
@patch("ai.summary_generator.build_context", new_callable=AsyncMock)
@patch("rag.retriever.get_retriever")
async def test_generate_incident_summary_auto_loads_default_retriever(mock_get_retriever, mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_retriever = AsyncMock()
    mock_retriever.retrieve.return_value = [
        {"title": "Auto-Loaded Playbook", "text": "Procedural guidance"}
    ]
    mock_get_retriever.return_value = mock_retriever
    mock_call_llm.return_value = "Summary text [EV-001]."

    # Calling without passing rag_retriever
    summary = await generate_incident_summary(
        db=AsyncMock(),
        incident_id=uuid.uuid4(),
        rag_retriever=None,
    )

    assert summary is not None
    mock_retriever.retrieve.assert_called_once()
    sys_prompt = mock_call_llm.call_args[0][0]
    assert "Auto-Loaded Playbook" in sys_prompt


@patch("ai.summary_generator.call_llm", new_callable=AsyncMock)
@patch("ai.summary_generator.build_context", new_callable=AsyncMock)
async def test_generate_incident_summary_rag_retrieval_failure_still_succeeds(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_rag_retriever = AsyncMock()
    mock_rag_retriever.retrieve.side_effect = RuntimeError("ChromaDB down")

    mock_call_llm.return_value = "Summary generated without RAG [EV-001]."

    summary = await generate_incident_summary(
        db=AsyncMock(),
        incident_id=uuid.uuid4(),
        rag_retriever=mock_rag_retriever,
    )

    assert summary is not None
    assert "Summary generated without RAG [EV-001]." in summary


@patch("ai.summary_generator.call_llm", new_callable=AsyncMock)
@patch("ai.summary_generator.build_context", new_callable=AsyncMock)
async def test_generate_incident_summary_unverified_citation_flagged(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()

    # Model hallucinates citation EV-999
    mock_call_llm.return_value = "Admin logged in [EV-001] and downloaded file [EV-999]."

    summary = await generate_incident_summary(
        db=AsyncMock(),
        incident_id=uuid.uuid4(),
        rag_retriever=None,
    )

    assert summary is not None
    assert "[EV-001]" in summary
    assert "[EV-999⚠️UNVERIFIED]" in summary


@patch("ai.summary_generator.call_llm", new_callable=AsyncMock)
@patch("ai.summary_generator.build_context", new_callable=AsyncMock)
async def test_generate_incident_summary_graceful_failure_returns_none(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_call_llm.side_effect = RuntimeError("All LLM providers unavailable")

    summary = await generate_incident_summary(
        db=AsyncMock(),
        incident_id=uuid.uuid4(),
    )

    # Must return None without raising exception
    assert summary is None


@patch("ai.summary_generator.build_context", new_callable=AsyncMock)
async def test_generate_incident_summary_nonexistent_incident(mock_build_context):
    mock_build_context.return_value = {"incident": None, "context_text": "", "evidence_map": {}}

    summary = await generate_incident_summary(
        db=AsyncMock(),
        incident_id=uuid.uuid4(),
    )

    assert summary is None
