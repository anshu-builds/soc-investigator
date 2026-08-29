from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rag.retriever import VectorStore

PLAYBOOK_DIR = Path(__file__).parent.parent.parent / "knowledge" / "playbooks"


def ingest_playbooks() -> None:
    store = VectorStore()
    documents = []
    metadatas = []
    ids = []

    for md_file in PLAYBOOK_DIR.glob("*.md"):
        text = md_file.read_text(encoding="utf-8")
        chunks = _chunk_text(text, chunk_size=500, overlap=100)
        for i, chunk in enumerate(chunks):
            doc_id = f"playbook_{md_file.stem}_{i}"
            documents.append(chunk)
            metadatas.append({
                "source": "playbook",
                "title": md_file.stem.replace("_", " ").title(),
                "file": md_file.name,
            })
            ids.append(doc_id)

    if documents:
        store.upsert(documents, metadatas, ids)
        print(f"[RAG] Ingested {len(documents)} playbook chunks from {PLAYBOOK_DIR}")
    else:
        print(f"[RAG] No playbook files found in {PLAYBOOK_DIR}")


def _chunk_text(text: str, chunk_size: int = 500, overlap: int = 100) -> list[str]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start = end - overlap
    return [c for c in chunks if len(c.strip()) > 50]


def ensure_playbooks_ingested() -> bool:
    """Ingest playbooks if the ChromaDB knowledge collection is empty."""
    try:
        store = VectorStore()
        if store.count() == 0:
            print("[RAG] ChromaDB knowledge collection empty. Auto-ingesting playbooks...")
            ingest_playbooks()
            return True
        return False
    except Exception as e:
        print(f"[RAG] Startup playbook ingestion check skipped: {e}")
        return False


if __name__ == "__main__":
    ingest_playbooks()
