from __future__ import annotations

import re
from typing import Dict, List, Tuple


EV_PATTERN = re.compile(r"\[EV-(\d{3,})\]")
MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_and_validate_citations(
    llm_response: str,
    evidence_map: Dict[str, str],
) -> Tuple[List[str], List[str], str]:
    cited_keys = EV_PATTERN.findall(llm_response)
    full_keys = [f"EV-{n}" for n in cited_keys]

    valid_uuids: List[str] = []
    invalid_keys: List[str] = []
    cleaned = llm_response

    # Flag evidence keys not present in the incident context
    for key in set(full_keys):
        if key in evidence_map:
            valid_uuids.append(evidence_map[key])
        else:
            invalid_keys.append(key)
            cleaned = cleaned.replace(f"[{key}]", f"[{key}⚠️UNVERIFIED]")

    return valid_uuids, invalid_keys, cleaned


def extract_mitre_references(llm_response: str) -> List[str]:
    return list(set(MITRE_PATTERN.findall(llm_response)))


def extract_rag_sources(rag_chunks: List[Dict]) -> List[str]:
    sources = []
    for chunk in rag_chunks:
        if isinstance(chunk, dict):
            title = chunk.get("title") or chunk.get("source") or "MITRE ATT&CK"
            sources.append(title)
    return list(dict.fromkeys(sources))


def classify_answer_type(llm_response: str) -> str:
    lower = llm_response.lower()
    has_citations = bool(EV_PATTERN.search(llm_response))
    has_inference = any(kw in lower for kw in ["suggests", "likely", "could indicate", "appears to", "may be"])
    has_recommendation = any(kw in lower for kw in ["should", "recommend", "next step", "containment", "isolate"])

    if has_recommendation and not has_citations:
        return "RECOMMENDATION"
    elif has_inference and not has_citations:
        return "INFERENCE"
    else:
        return "FACTUAL"
