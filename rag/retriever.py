"""RAG knowledge retriever supporting ChromaDB vector search with local playbook fallback."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_settings
from rag.fallback_retriever import FallbackRetriever, get_fallback_retriever

logger = logging.getLogger("soc.rag.retriever")
settings = get_settings()


class VectorStore:
    """ChromaDB-backed vector collection manager."""

    def __init__(self) -> None:
        import chromadb
        self._client = chromadb.HttpClient(
            host=settings.chroma_host,
            port=settings.chroma_port,
        )
        self._collection_name = settings.chroma_collection_knowledge
        self._collection = None

    def get_or_create_collection(self):
        if self._collection is None:
            import chromadb.utils.embedding_functions as ef
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                embedding_function=ef.SentenceTransformerEmbeddingFunction(
                    model_name="all-MiniLM-L6-v2"
                ),
            )
        return self._collection

    def count(self) -> int:
        col = self.get_or_create_collection()
        return col.count()

    def upsert(self, documents: List[str], metadatas: List[Dict], ids: List[str]) -> None:
        col = self.get_or_create_collection()
        col.upsert(documents=documents, metadatas=metadatas, ids=ids)

    def query(self, query_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        col = self.get_or_create_collection()
        results = col.query(query_texts=[query_text], n_results=top_k)
        chunks = []
        for i, doc in enumerate(results.get("documents", [[]])[0]):
            meta = (results.get("metadatas", [[]])[0] or [{}])[i]
            chunks.append({
                "text": doc,
                "title": meta.get("title", ""),
                "source": meta.get("source", "chromadb"),
                "distance": (results.get("distances", [[]])[0] or [1.0])[i],
            })
        return chunks


class Retriever:
    """Hybrid RAG retriever: uses ChromaDB vector store primarily with local keyword fallback."""

    def __init__(
        self,
        store: Optional[VectorStore] = None,
        fallback: Optional[FallbackRetriever] = None,
    ) -> None:
        self._store = store
        self._fallback = fallback or get_fallback_retriever()
        self._store_init_attempted = False

    def _get_store(self) -> Optional[VectorStore]:
        if self._store is None and not self._store_init_attempted:
            self._store_init_attempted = True
            try:
                self._store = VectorStore()
            except Exception as exc:
                logger.warning("ChromaDB VectorStore initialization failed: %s. Local fallback active.", exc)
                self._store = None
        return self._store

    async def retrieve(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Retrieve relevant knowledge chunks using ChromaDB with automatic local fallback."""
        store = self._get_store()
        if store is not None:
            try:
                results = store.query(query, top_k=top_k)
                if results:
                    return results
                logger.info("ChromaDB returned 0 results; querying local playbook fallback.")
            except Exception as e:
                logger.warning("ChromaDB query failed: %s. Activating local playbook fallback.", e)

        # Fallback path: Local in-memory playbook keyword retrieval
        try:
            return self._fallback.retrieve(query, top_k=top_k)
        except Exception as fallback_exc:
            logger.error("Local playbook fallback retrieval failed: %s", fallback_exc)
            return []


_retriever_instance: Optional[Retriever] = None


def get_retriever() -> Retriever:
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = Retriever()
    return _retriever_instance
