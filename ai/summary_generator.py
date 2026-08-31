from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ai.context_builder import build_context
from ai.evidence_linker import extract_and_validate_citations
from ai.llm_client import call_llm
from ai.prompt_templates import build_summary_system_prompt, build_summary_user_prompt

logger = logging.getLogger("soc.ai")


async def generate_incident_summary(
    db: AsyncSession,
    incident_id: uuid.UUID,
    rag_retriever: Any = None,
) -> Optional[str]:
    """Generate an evidence-grounded AI executive summary for an incident report.

    Gracefully falls back to None if the LLM is unavailable or unconfigured,
    ensuring report generation never fails.
    """
    try:
        context = await build_context(db, incident_id)
        incident = context.get("incident")
        if not incident:
            logger.warning("Cannot generate AI summary: Incident %s not found", incident_id)
            return None

        evidence_map = context.get("evidence_map", {})
        incident_context = context.get("context_text", "")

        rag_context = ""
        if rag_retriever is None:
            try:
                from rag.retriever import get_retriever
                rag_retriever = get_retriever()
            except Exception as e:
                logger.debug("Failed to obtain default RAG retriever: %s", e)
                rag_retriever = None

        if rag_retriever is not None:
            try:
                technique_ids = [t.technique_id for t in context.get("techniques", [])]
                query = f"{incident.title} {incident.attack_type} {' '.join(technique_ids)}"
                rag_chunks = await rag_retriever.retrieve(query, top_k=2)
                rag_context = "\n\n".join(
                    f"[{c.get('title', 'Reference')}]\n{c.get('text', '')}"
                    for c in rag_chunks
                    if isinstance(c, dict)
                )
            except Exception as rag_err:
                logger.debug("RAG retrieval failed during summary generation: %s", rag_err)

        system_prompt = build_summary_system_prompt(
            incident_context=incident_context,
            rag_context=rag_context,
        )
        user_prompt = build_summary_user_prompt()

        raw_response = await call_llm(system_prompt, user_prompt)
        if not raw_response or not raw_response.strip():
            return None

        _valid_uuids, invalid_keys, cleaned_response = extract_and_validate_citations(
            raw_response, evidence_map
        )

        if invalid_keys:
            logger.warning(
                "AI summary for incident %s cited unverified evidence keys: %s",
                incident_id,
                invalid_keys,
            )

        return cleaned_response.strip()

    except Exception as e:
        logger.warning(
            "AI incident summary generation failed for incident %s: %s",
            incident_id,
            e,
        )
        return None
