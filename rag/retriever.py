from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_settings

settings = get_settings()


class VectorStore:
    def __init__(self) -> None:
        import chromadb
        self._client = chromadb.HttpClient(
            host=settings.chroma_host,
            port=settings.chroma_port,
        )
        self._collection_name = settings.chroma_collection_knowledge
        self._collection = None

    def get_or_create_collection(self):
        import chromadb.utils.embedding_functions as ef
        self._collection = self._client.get_or_create_collection(
            name=self._collection_name,
            embedding_function=ef.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            ),
        )
        return self._collection

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
                "source": meta.get("source", ""),
                "distance": (results.get("distances", [[]])[0] or [1.0])[i],
            })
        return chunks


class Retriever:
    def __init__(self, store: Optional[VectorStore] = None) -> None:
        self._store = store or VectorStore()

    async def retrieve(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        try:
            return self._store.query(query, top_k=top_k)
        except Exception as e:
            print(f"[RAG] ChromaDB query failed: {e}")
            return []


_retriever_instance: Optional[Retriever] = None


def get_retriever() -> Retriever:
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = Retriever()
    return _retriever_instance
