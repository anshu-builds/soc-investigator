"""
Evidence Linker — Post-processing step

Parses LLM response text for [EV-NNN] citations, validates them against
the known evidence_map, and extracts MITRE technique references.

Prevents hallucinated evidence IDs from reaching the user.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple


EV_PATTERN = re.compile(r"\[EV-(\d{3,})\]")
MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_and_validate_citations(
    llm_response: str,
    evidence_map: Dict[str, str],  # "EV-001" → real UUID string
) -> Tuple[List[str], List[str], str]:
    """
    Parse LLM response for [EV-NNN] citations and validate them.

    Returns:
        (valid_evidence_ids, invalid_keys, cleaned_response)
        - valid_evidence_ids: list of real UUID strings for valid citations
        - invalid_keys: list of [EV-NNN] keys that were NOT in our evidence_map
        - cleaned_response: response with invalid citations marked
    """
    cited_keys = EV_PATTERN.findall(llm_response)
    full_keys = [f"EV-{n}" for n in cited_keys]

    valid_uuids: List[str] = []
    invalid_keys: List[str] = []
    cleaned = llm_response

    for key in set(full_keys):
        if key in evidence_map:
            valid_uuids.append(evidence_map[key])
        else:
            invalid_keys.append(key)
            # Mark invalid citations in the response
            cleaned = cleaned.replace(f"[{key}]", f"[{key}⚠️UNVERIFIED]")

    return valid_uuids, invalid_keys, cleaned


def extract_mitre_references(llm_response: str) -> List[str]:
    """Extract MITRE ATT&CK technique IDs (e.g., T1110, T1078.003) from response."""
    return list(set(MITRE_PATTERN.findall(llm_response)))


def extract_rag_sources(rag_chunks: List[Dict]) -> List[str]:
    """Format RAG chunks into human-readable source strings."""
    sources = []
    for chunk in rag_chunks:
        if isinstance(chunk, dict):
            title = chunk.get("title") or chunk.get("source") or "MITRE ATT&CK"
            sources.append(title)
    return list(dict.fromkeys(sources))  # Deduplicate while preserving order


def classify_answer_type(llm_response: str) -> str:
    """
    Classify the answer type: FACTUAL, INFERENCE, or RECOMMENDATION.

    Heuristics:
    - Contains "[EV-" citations → likely FACTUAL
    - Contains "suggests", "likely", "could indicate" → INFERENCE
    - Contains "should", "recommend", "next step" → RECOMMENDATION
    """
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
