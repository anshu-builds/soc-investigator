"""Unit tests for context_builder and chat history formatting."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock
import pytest

from ai.context_builder import format_chat_history, _format_chat_history, _format_context
from backend.models import ChatMessage, Evidence, Incident, SecurityEvent


class TestFormatChatHistory:
    def test_empty_or_none_history_returns_empty_string(self):
        assert format_chat_history(None) == ""
        assert format_chat_history([]) == ""
        assert _format_chat_history(None) == ""

    def test_dict_messages_formatted_properly(self):
        history = [
            {"role": "user", "content": "What is the source IP of the attacker?"},
            {"role": "assistant", "content": "The attacker originated from 192.168.1.50 [EV-001]."},
            {"role": "user", "content": "Did they compromise any user accounts?"},
        ]
        formatted = format_chat_history(history)
        assert "<conversation_history>" in formatted
        assert '<message role="analyst">What is the source IP of the attacker?</message>' in formatted
        assert '<message role="assistant">The attacker originated from 192.168.1.50 [EV-001].</message>' in formatted
        assert '<message role="analyst">Did they compromise any user accounts?</message>' in formatted
        assert "</conversation_history>" in formatted

    def test_chat_message_objects_formatted_properly(self):
        msg1 = ChatMessage(
            id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            role="user",
            content="Can you summarize the attack?",
        )
        msg2 = ChatMessage(
            id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            role="assistant",
            content="Summary of attack: Brute force followed by privilege escalation [EV-001].",
        )
        formatted = format_chat_history([msg1, msg2])
        assert '<message role="analyst">Can you summarize the attack?</message>' in formatted
        assert '<message role="assistant">Summary of attack: Brute force followed by privilege escalation [EV-001].</message>' in formatted

    def test_empty_content_messages_skipped(self):
        history = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "   "},
            {"role": "user", "content": ""},
            {"role": "assistant", "content": "How can I help you investigate?"},
        ]
        formatted = format_chat_history(history)
        assert '<message role="analyst">Hello</message>' in formatted
        assert '<message role="assistant">How can I help you investigate?</message>' in formatted
        assert formatted.count("<message") == 2
