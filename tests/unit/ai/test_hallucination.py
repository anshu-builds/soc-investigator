import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from ai.investigation_chain import run_investigation_chain

pytestmark = pytest.mark.asyncio


def _mock_incident_context():
    mock_incident = MagicMock()
    mock_incident.attack_type = "BRUTE_FORCE"
    return {
        "incident": mock_incident,
        "context_text": "- **22:00:00 UTC** User `admin` failed SSH login from 10.1.2.3 [EV-100]\n"
                        "- **22:00:15 UTC** User `admin` successful login from 10.1.2.3 [EV-101]",
        "evidence_map": {"EV-100": "uuid-100", "EV-101": "uuid-101"},
        "techniques": []
    }


@patch("ai.investigation_chain.call_llm", new_callable=AsyncMock)
@patch("ai.investigation_chain.build_context", new_callable=AsyncMock)
async def test_hallucination_unsupported_ip(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_rag_retriever = AsyncMock()
    mock_rag_retriever.retrieve.return_value = []

    mock_call_llm.return_value = """
## Summary
I cannot determine this from the available evidence.

## Assessment
The available evidence does not establish any activity from IP 10.9.9.9.
    """

    result = await run_investigation_chain(
        db=None,
        incident_id="incident1",
        user_question="What happened with IP 10.9.9.9?",
        rag_retriever=mock_rag_retriever,
        chat_history=[]
    )

    assert result["answer_type"] == "CANNOT_DETERMINE"
    assert len(result["evidence_ids"]) == 0

    sys_prompt = mock_call_llm.call_args[0][0]
    assert "I cannot determine this from the available evidence" in sys_prompt
    assert "Do NOT fabricate IP addresses" in sys_prompt
    assert "10.1.2.3" in sys_prompt


@patch("ai.investigation_chain.call_llm", new_callable=AsyncMock)
@patch("ai.investigation_chain.build_context", new_callable=AsyncMock)
async def test_hallucination_unsupported_username(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_rag_retriever = AsyncMock()
    mock_rag_retriever.retrieve.return_value = []

    mock_call_llm.return_value = """
## Summary
I cannot determine this from the available evidence. Insufficient information regarding user alice.
    """

    result = await run_investigation_chain(
        db=None,
        incident_id="incident1",
        user_question="Did user alice log in?",
        rag_retriever=mock_rag_retriever,
        chat_history=[]
    )

    assert result["answer_type"] == "CANNOT_DETERMINE"
    assert len(result["evidence_ids"]) == 0


@patch("ai.investigation_chain.call_llm", new_callable=AsyncMock)
@patch("ai.investigation_chain.build_context", new_callable=AsyncMock)
async def test_hallucination_unsupported_timestamp(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_rag_retriever = AsyncMock()
    mock_rag_retriever.retrieve.return_value = []

    mock_call_llm.return_value = """
## Summary
There is no evidence to suggest activity occurred in 2029.
    """

    result = await run_investigation_chain(
        db=None,
        incident_id="incident1",
        user_question="What happened in year 2029?",
        rag_retriever=mock_rag_retriever,
        chat_history=[]
    )

    assert result["answer_type"] == "CANNOT_DETERMINE"
    assert len(result["evidence_ids"]) == 0


@patch("ai.investigation_chain.call_llm", new_callable=AsyncMock)
@patch("ai.investigation_chain.build_context", new_callable=AsyncMock)
async def test_fabricated_citation_flagged_and_unverified(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_rag_retriever = AsyncMock()
    mock_rag_retriever.retrieve.return_value = []

    # LLM hallucinates an unverified citation [EV-999] alongside valid [EV-100]
    mock_call_llm.return_value = """
## Summary
Admin failed login [EV-100], and then accessed database [EV-999].
    """

    result = await run_investigation_chain(
        db=None,
        incident_id="incident1",
        user_question="What happened?",
        rag_retriever=mock_rag_retriever,
        chat_history=[]
    )

    # EV-999 must NOT be in evidence_ids
    assert result["evidence_ids"] == ["uuid-100"]
    # Answer text must have flagged the fake key
    assert "[EV-999⚠️UNVERIFIED]" in result["answer"]
    assert "[EV-100]" in result["answer"]


@patch("ai.investigation_chain.call_llm", new_callable=AsyncMock)
@patch("ai.investigation_chain.build_context", new_callable=AsyncMock)
async def test_factual_answer_preservation(mock_build_context, mock_call_llm):
    mock_build_context.return_value = _mock_incident_context()
    mock_rag_retriever = AsyncMock()
    mock_rag_retriever.retrieve.return_value = []

    mock_call_llm.return_value = """
## Summary
Admin logged in successfully from 10.1.2.3 [EV-101].
    """

    result = await run_investigation_chain(
        db=None,
        incident_id="incident1",
        user_question="What IP did admin use?",
        rag_retriever=mock_rag_retriever,
        chat_history=[]
    )

    assert result["answer_type"] == "FACTUAL"
    assert result["evidence_ids"] == ["uuid-101"]
