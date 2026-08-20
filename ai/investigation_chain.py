"""
Investigation Chain — Full AI Pipeline Orchestrator

Flow:
  context_builder → RAG retrieval → prompt_constructor → LLM → evidence_linker → response
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ai.context_builder import build_context
from ai.evidence_linker import (
    classify_answer_type,
    extract_and_validate_citations,
    extract_mitre_references,
    extract_rag_sources,
)
from ai.llm_client import call_llm
from ai.prompt_templates import build_system_prompt, build_user_prompt


async def run_investigation_chain(
    db: AsyncSession,
    incident_id: uuid.UUID,
    user_question: str,
    rag_retriever=None,  # Optional: rag.retriever.Retriever instance
) -> Dict[str, Any]:
    """
    Full AI investigation pipeline.

    Returns a structured response dict ready for the API.
    """
    # Step 1: Build incident context from DB
    context = await build_context(db, incident_id)
    incident_context = context["context_text"]
    evidence_map = context["evidence_map"]  # "EV-001" → UUID string

    if not context["incident"]:
        return {
            "answer": "Incident not found in the database.",
            "evidence_ids": [],
            "mitre_references": [],
            "rag_sources": [],
            "answer_type": "FACTUAL",
            "confidence": 0.0,
        }

    # Step 2: RAG retrieval
    rag_chunks: List[Dict] = []
    rag_context = ""
    if rag_retriever is not None:
        try:
            incident = context["incident"]
            technique_ids = [t.technique_id for t in context.get("techniques", [])]
            query = f"{user_question} {incident.attack_type} {' '.join(technique_ids)}"
            rag_chunks = await rag_retriever.retrieve(query, top_k=3)
            rag_context = "\n\n".join(
                f"[{c.get('title', 'Reference')}]\n{c.get('text', '')}"
                for c in rag_chunks
            )
        except Exception as e:
            print(f"[RAG] Retrieval failed: {e}")

    # Step 3: Construct prompts
    system_prompt = build_system_prompt(incident_context, rag_context)
    user_prompt = build_user_prompt(user_question)

    # Step 4: LLM call
    raw_response = await call_llm(system_prompt, user_prompt)

    # Step 5: Evidence validation
    valid_uuids, invalid_keys, cleaned_response = extract_and_validate_citations(
        raw_response, evidence_map
    )

    if invalid_keys:
        print(f"[AI] WARNING: LLM cited non-existent evidence keys: {invalid_keys}")

    mitre_refs = extract_mitre_references(cleaned_response)
    rag_sources = extract_rag_sources(rag_chunks)
    answer_type = classify_answer_type(cleaned_response)

    # Confidence: based on citation density and evidence map coverage
    cited_ratio = len(valid_uuids) / max(len(evidence_map), 1)
    confidence = min(0.5 + cited_ratio * 0.5, 0.98) if valid_uuids else 0.55

    return {
        "answer": cleaned_response,
        "evidence_ids": valid_uuids,
        "mitre_references": mitre_refs,
        "rag_sources": rag_sources,
        "rag_chunks_raw": rag_chunks,
        "answer_type": answer_type,
        "confidence": round(confidence, 3),
    }
