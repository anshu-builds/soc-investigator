"""Unit tests for the AI investigation chain."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch
import pytest

from ai.investigation_chain import run_investigation_chain


class TestInvestigationChain:
    @pytest.mark.asyncio
    async def test_first_turn_empty_history(self):
        incident_id = uuid.uuid4()
        ev_id = uuid.uuid4()

        mock_context = {
            "incident": AsyncMock(attack_type="BRUTE_FORCE"),
            "context_text": "INCIDENT: Brute Force\n[EV-001] SSH failure",
            "evidence_map": {"EV-001": str(ev_id)},
            "techniques": [AsyncMock(technique_id="T1110")],
        }

        mock_llm_response = (
            "## Summary\n"
            "An attacker conducted brute force authentication attempts [EV-001].\n\n"
            "## Evidence\n"
            "- [EV-001] SSH auth failure\n\n"
            "## MITRE ATT&CK\n"
            "- T1110 — Brute Force\n\n"
            "## Recommended Actions\n"
            "1. Block IP address.\n\n"
            "## Confidence\n"
            "**90%**"
        )

        with patch("ai.investigation_chain.build_context", new_callable=AsyncMock) as mock_ctx, \
             patch("ai.investigation_chain.call_llm", new_callable=AsyncMock) as mock_llm:

            mock_ctx.return_value = mock_context
            mock_llm.return_value = mock_llm_response

            mock_db = AsyncMock()
            result = await run_investigation_chain(
                db=mock_db,
                incident_id=incident_id,
                user_question="What happened?",
                chat_history=None,
            )

            assert str(ev_id) in result["evidence_ids"]
            assert "T1110" in result["mitre_references"]
            assert result["answer_type"] in ("FACTUAL", "RECOMMENDATION", "INFERENCE")
            assert result["confidence"] > 0.5
            mock_llm.assert_called_once()

            # Ensure system prompt had default empty history text
            call_sys_prompt = mock_llm.call_args[0][0]
            assert "No previous conversation history." in call_sys_prompt

    @pytest.mark.asyncio
    async def test_second_turn_passes_conversation_history(self):
        incident_id = uuid.uuid4()
        ev_id = uuid.uuid4()

        mock_context = {
            "incident": AsyncMock(attack_type="BRUTE_FORCE"),
            "context_text": "INCIDENT: Brute Force\n[EV-001] SSH failure",
            "evidence_map": {"EV-001": str(ev_id)},
            "techniques": [AsyncMock(technique_id="T1110")],
        }

        history = [
            {"role": "user", "content": "What is the attacking IP?"},
            {"role": "assistant", "content": "The attacker IP is 192.168.1.50 [EV-001]."},
        ]

        with patch("ai.investigation_chain.build_context", new_callable=AsyncMock) as mock_ctx, \
             patch("ai.investigation_chain.call_llm", new_callable=AsyncMock) as mock_llm:

            mock_ctx.return_value = mock_context
            mock_llm.return_value = "## Summary\nFollow up response [EV-001]."

            mock_db = AsyncMock()
            result = await run_investigation_chain(
                db=mock_db,
                incident_id=incident_id,
                user_question="What should we do with that IP?",
                chat_history=history,
            )

            mock_llm.assert_called_once()
            call_sys_prompt = mock_llm.call_args[0][0]
            assert "Analyst: What is the attacking IP?" in call_sys_prompt
            assert "Assistant: The attacker IP is 192.168.1.50 [EV-001]." in call_sys_prompt

    @pytest.mark.asyncio
    async def test_incident_not_found(self):
        with patch("ai.investigation_chain.build_context", new_callable=AsyncMock) as mock_ctx:
            mock_ctx.return_value = {"incident": None, "context_text": "", "evidence_map": {}}

            mock_db = AsyncMock()
            result = await run_investigation_chain(
                db=mock_db,
                incident_id=uuid.uuid4(),
                user_question="Explain this incident",
            )

            assert "Incident not found" in result["answer"]
            assert result["evidence_ids"] == []
            assert result["confidence"] == 0.0
