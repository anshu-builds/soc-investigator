"""Unit tests for the hybrid Retriever (ChromaDB + Local Fallback)."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from rag.fallback_retriever import FallbackRetriever
from rag.retriever import Retriever


class TestHybridRetriever:
    @pytest.mark.asyncio
    async def test_chromadb_normal_path_when_available(self):
        mock_store = MagicMock()
        mock_store.query.return_value = [
            {"text": "Vector result 1", "title": "Vector Doc", "source": "chromadb", "distance": 0.1}
        ]
        mock_fallback = MagicMock()

        retriever = Retriever(store=mock_store, fallback=mock_fallback)
        results = await retriever.retrieve("brute force containment", top_k=2)

        assert len(results) == 1
        assert results[0]["title"] == "Vector Doc"
        mock_store.query.assert_called_once_with("brute force containment", top_k=2)
        # Fallback was not needed
        mock_fallback.retrieve.assert_not_called()

    @pytest.mark.asyncio
    async def test_chromadb_exception_activates_fallback(self):
        mock_store = MagicMock()
        mock_store.query.side_effect = ConnectionError("ChromaDB HTTP connection refused on port 8001")

        mock_fallback = MagicMock()
        mock_fallback.retrieve.return_value = [
            {"text": "Fallback result", "title": "Local Playbook", "source": "playbook", "file": "brute_force_response.md"}
        ]

        retriever = Retriever(store=mock_store, fallback=mock_fallback)
        results = await retriever.retrieve("brute force containment", top_k=3)

        assert len(results) == 1
        assert results[0]["title"] == "Local Playbook"
        assert results[0]["source"] == "playbook"
        mock_store.query.assert_called_once()
        mock_fallback.retrieve.assert_called_once_with("brute force containment", top_k=3)

    @pytest.mark.asyncio
    async def test_chromadb_empty_results_activates_fallback(self):
        mock_store = MagicMock()
        mock_store.query.return_value = []

        mock_fallback = MagicMock()
        mock_fallback.retrieve.return_value = [
            {"text": "Fallback result", "title": "Account Compromise Response", "source": "playbook"}
        ]

        retriever = Retriever(store=mock_store, fallback=mock_fallback)
        results = await retriever.retrieve("account compromise", top_k=2)

        assert len(results) == 1
        assert results[0]["title"] == "Account Compromise Response"
        mock_store.query.assert_called_once()
        mock_fallback.retrieve.assert_called_once_with("account compromise", top_k=2)

    @pytest.mark.asyncio
    async def test_fallback_with_real_local_playbooks_when_no_chromadb(self):
        # Pass no store (or uninitialized) and real FallbackRetriever
        fallback = FallbackRetriever()
        # Mock store failure
        mock_store = MagicMock()
        mock_store.query.side_effect = RuntimeError("No ChromaDB server")

        retriever = Retriever(store=mock_store, fallback=fallback)
        results = await retriever.retrieve("privilege escalation remediation steps", top_k=2)

        assert len(results) > 0
        assert any("Privilege Escalation" in r["title"] for r in results)
        assert results[0]["source"] == "playbook"
