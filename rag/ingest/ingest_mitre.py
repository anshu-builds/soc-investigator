from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.security import SSRFSecurityError, validate_url_ssrf
from rag.retriever import VectorStore

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MAX_MITRE_STIX_BYTES = 50 * 1024 * 1024  # 50 MB


def ingest_mitre() -> None:
    print("[RAG] Validating MITRE ATT&CK source URL...")
    try:
        validated = validate_url_ssrf(MITRE_URL, allow_private=False, allow_loopback=False)
    except SSRFSecurityError as exc:
        raise RuntimeError(f"MITRE STIX URL rejected by SSRF security policy: {exc}") from exc

    print("[RAG] Downloading MITRE ATT&CK STIX JSON...")
    req = urllib.request.Request(
        validated.url,
        headers={"User-Agent": "SOC-Investigator-RAG/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15.0) as response:
        raw_bytes = response.read(MAX_MITRE_STIX_BYTES + 1)
        if len(raw_bytes) > MAX_MITRE_STIX_BYTES:
            raise RuntimeError(f"MITRE STIX JSON exceeds maximum allowed size of {MAX_MITRE_STIX_BYTES} bytes")
        data = json.loads(raw_bytes.decode("utf-8"))

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
