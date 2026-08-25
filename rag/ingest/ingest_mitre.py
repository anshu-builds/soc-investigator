from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rag.retriever import VectorStore

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def ingest_mitre() -> None:
    print("[RAG] Downloading MITRE ATT&CK STIX JSON...")
    req = urllib.request.Request(MITRE_URL)
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read())

    print("[RAG] Parsing techniques...")
    documents = []
    metadatas = []
    ids = []

    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            tech_id = next(
                (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None
            )
            if not tech_id:
                continue

            name = obj.get("name", "")
            description = obj.get("description", "")
            url = next(
                (r.get("url") for r in ext_refs if r.get("source_name") == "mitre-attack"),
                ""
            )

            if description:
                documents.append(f"{tech_id}: {name}\n{description}"[:1000])
                metadatas.append({
                    "source": "mitre-attack",
                    "title": f"MITRE {tech_id}: {name}",
                    "technique_id": tech_id,
                    "url": url,
                })
                ids.append(f"mitre_{tech_id}")

    if documents:
        store = VectorStore()
        store.upsert(documents, metadatas, ids)
        print(f"[RAG] Ingested {len(documents)} MITRE techniques into ChromaDB.")
    else:
        print("[RAG] No techniques parsed.")


if __name__ == "__main__":
    ingest_mitre()
