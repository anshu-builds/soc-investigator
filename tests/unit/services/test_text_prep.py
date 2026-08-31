from backend.services.text_prep import chunk_for_tts, sanitize_for_speech, prepare_for_speech


def test_sanitizes_soc_markdown_and_evidence_ids():
    raw = "## Summary\n- **Likely attack** via `T1059`. See [EV-003].\n- [EV-004⚠️UNVERIFIED] needs review."
    out = sanitize_for_speech(raw)
    assert "Summary." in out
    assert "Likely attack via T1059." in out
    assert "evidence 3" in out
    assert "evidence 4, unverified" in out
    assert "##" not in out
    assert "**" not in out


def test_chunks_under_sarvam_limit():
    raw = " ".join(["This is a sentence."] * 300)
    chunks = chunk_for_tts(raw, max_chars=2500)
    assert len(chunks) > 1
    assert all(len(chunk) <= 2500 for chunk in chunks)


def test_prepare_for_speech_empty_input():
    assert prepare_for_speech("") == []
