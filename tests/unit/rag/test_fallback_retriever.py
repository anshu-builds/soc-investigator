"""Unit tests for the zero-dependency local FallbackRetriever."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from rag.fallback_retriever import FallbackRetriever, _tokenize


class TestFallbackRetriever:
    def test_tokenization(self):
        tokens = _tokenize("Brute Force Attack Containment Steps!")
        assert "brute" in tokens
        assert "force" in tokens
        assert "attack" in tokens
        assert "containment" in tokens
        assert "steps" in tokens
        # Stopwords removed
        assert "in" not in _tokenize("Brute force in the cloud")

    def test_empty_query_returns_empty_list(self):
        retriever = FallbackRetriever()
        assert retriever.retrieve("") == []
        assert retriever.retrieve("   ") == []

    def test_brute_force_query_retrieves_brute_force_playbook(self):
        retriever = FallbackRetriever()
        results = retriever.retrieve("brute force attack containment", top_k=2)

        assert len(results) > 0
        assert any(r["file"] == "brute_force_response.md" for r in results)
        assert any("Brute Force" in r["title"] for r in results)
        assert "source" in results[0]
        assert results[0]["source"] == "playbook"

    def test_account_compromise_query_retrieves_compromise_playbook(self):
        retriever = FallbackRetriever()
        results = retriever.retrieve("account compromise response steps", top_k=2)

        assert len(results) > 0
        assert any(r["file"] == "account_compromise_response.md" for r in results)
        assert any("Account Compromise" in r["title"] for r in results)

    def test_privilege_escalation_query_retrieves_escalation_playbook(self):
        retriever = FallbackRetriever()
        results = retriever.retrieve("privilege escalation remediation", top_k=2)

        assert len(results) > 0
        assert any(r["file"] == "privilege_escalation_response.md" for r in results)
        assert any("Privilege Escalation" in r["title"] for r in results)

    def test_lateral_movement_query_retrieves_lateral_movement_playbook(self):
        retriever = FallbackRetriever()
        results = retriever.retrieve("lateral movement investigation", top_k=2)

        assert len(results) > 0
        assert any(r["file"] == "lateral_movement_response.md" for r in results)

    def test_credential_dumping_query_retrieves_dumping_playbook(self):
        retriever = FallbackRetriever()
        results = retriever.retrieve("credential dumping containment", top_k=2)

        assert len(results) > 0
        assert any(r["file"] == "credential_dumping_response.md" for r in results)

    def test_top_k_respected(self):
        retriever = FallbackRetriever()
        results_1 = retriever.retrieve("authentication security", top_k=1)
        results_3 = retriever.retrieve("authentication security", top_k=3)

        assert len(results_1) <= 1
        assert len(results_3) <= 3
        if len(results_3) > 1:
            assert len(results_3) > len(results_1)

    def test_unrelated_nonsense_query_returns_empty_list(self):
        retriever = FallbackRetriever()
        results = retriever.retrieve("xyzqwerty123456789 non-matching-gibberish")
        assert results == []

    def test_missing_or_malformed_playbook_directory_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_dir = Path(tmp_dir) / "corrupt_playbooks"
            bad_dir.mkdir()
            (bad_dir / "empty.md").write_text("", encoding="utf-8")
            (bad_dir / "valid.md").write_text("# Custom Playbook\n## Steps\nIsolate host.", encoding="utf-8")

            retriever = FallbackRetriever(playbook_dir=bad_dir)
            results = retriever.retrieve("isolate host")
            assert len(results) > 0
            assert "Custom Playbook" in results[0]["title"]
