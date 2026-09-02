from __future__ import annotations

import pytest

from backend.services.text_prep import TextPreparationError, chunk_for_tts, prepare_for_speech, sanitize_for_speech


def test_sanitize_for_speech_removes_formatting_urls_and_controls():
    text = "## **Summary**\n- [Investigate](https://internal.example/token) [EV-003]\x00"

    result = sanitize_for_speech(text)

    assert "Summary" in result
    assert "Investigate" in result
    assert "evidence 3" in result
    assert "https://" not in result
    assert "\x00" not in result
    assert "**" not in result


def test_prepare_rejects_pathological_and_sanitized_over_limit_input():
    with pytest.raises(TextPreparationError):
        prepare_for_speech("x" * 21, max_total_chars=10, max_chunks=1)

    with pytest.raises(TextPreparationError):
        prepare_for_speech("x" * 11, max_total_chars=10, max_chunks=1)


def test_chunking_respects_each_provider_and_aggregate_chunk_limit():
    text = "Alpha sentence. Bravo sentence. Charlie sentence."
    chunks = chunk_for_tts(text, max_chars=20, max_chunks=3)

    assert chunks
    assert all(len(chunk) <= 20 for chunk in chunks)

    with pytest.raises(TextPreparationError):
        chunk_for_tts(text, max_chars=20, max_chunks=1)


def test_short_message_synthesizes_normally():
    short_text = "The analyst investigated the alert and isolated the workstation."
    chunks = prepare_for_speech(short_text, max_total_chars=1000, max_chars_per_chunk=320, max_chunks=3)
    assert len(chunks) == 1
    assert chunks[0] == short_text


def test_long_message_converts_to_bounded_briefing():
    long_text = (
        "## Summary\n"
        "An attacker operating from IP 10.10.5.200 targeted the account sarah.miller.\n\n"
        "## Timeline\n" + "- 14:15:00 UTC Failed login attempt [EV-001]\n" * 50
    )
    chunks = prepare_for_speech(long_text, max_total_chars=1000, max_chars_per_chunk=320, max_chunks=3)
    assert 1 <= len(chunks) <= 3
    combined = " ".join(chunks)
    assert "An attacker operating from IP 10.10.5.200" in combined
    assert "Failed login attempt" not in combined
    assert "Full details and evidence remain in the console." in combined
    assert len(combined) <= 700


def test_briefing_handles_response_without_summary():
    no_summary_text = (
        "Based on the log evidence provided, the alert was triggered by an initial failed authentication. "
        "The security investigation indicates credential stuffing targeting the administrator account. "
        "Immediate password resets should be enforced across all affected systems.\n\n"
        + "Detailed log dump:\n" + "- Event log row\n" * 40
    )
    chunks = prepare_for_speech(no_summary_text, max_total_chars=1000, max_chars_per_chunk=320, max_chunks=3)
    assert 1 <= len(chunks) <= 3
    combined = " ".join(chunks)
    assert "Based on the log evidence" in combined
    assert "Event log row" not in combined
    assert "Full details and evidence remain in the console." in combined


def test_briefing_strips_tables_and_code_blocks():
    text_with_tables = (
        "## Summary\n"
        "Unauthorized API access detected on production gateway.\n\n"
        "| Timestamp | Source IP | User | Status |\n"
        "|---|---|---|---|\n"
        "| 12:00:00 | 192.168.1.1 | root | 401 |\n"
        "| 12:00:01 | 192.168.1.1 | root | 401 |\n\n"
        "```json\n"
        "{\"event\": \"bad_request\", \"raw_payload\": \"0xdeadbeef\"}\n"
        "```\n\n"
        "Recommended action: Block IP on WAF."
    )
    chunks = prepare_for_speech(text_with_tables, max_total_chars=1000, max_chars_per_chunk=320, max_chunks=3)
    combined = " ".join(chunks)
    assert "Unauthorized API access detected" in combined
    assert "0xdeadbeef" not in combined
    assert "Timestamp" not in combined
    assert "root" not in combined


def test_empty_and_whitespace_responses_return_empty():
    assert prepare_for_speech("", max_total_chars=1000, max_chunks=3) == []
    assert prepare_for_speech("   \n\t  ", max_total_chars=1000, max_chunks=3) == []


def test_pathological_input_exceeding_hard_limit_rejected():
    with pytest.raises(TextPreparationError):
        prepare_for_speech("x" * 10_001, max_total_chars=1000, max_chunks=3)

