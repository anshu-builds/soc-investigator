from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.models import AttackTechnique, Evidence, Incident
from ai.prompt_sanitizer import (
    escape_xml_text,
    serialize_conversation_history,
    serialize_untrusted_evidence,
)


async def build_context(
    db: AsyncSession,
    incident_id: uuid.UUID,
) -> Dict[str, Any]:
    result = await db.execute(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            selectinload(Incident.evidence).selectinload(Evidence.event),
            selectinload(Incident.techniques),
        )
    )
    incident: Optional[Incident] = result.scalar_one_or_none()

    if not incident:
        return {"context_text": "Incident not found.", "evidence_map": {}, "incident": None}

    # Map short citation IDs (EV-001) to database UUIDs
    evidence_items = sorted(
        incident.evidence,
        key=lambda e: (e.sequence_order or 999, str(e.id)),
    )
    evidence_map: Dict[str, str] = {}
    for i, ev in enumerate(evidence_items, start=1):
        short_key = f"EV-{i:03d}"
        evidence_map[short_key] = str(ev.id)

    context_text = _format_context(incident, evidence_items, evidence_map)

    return {
        "context_text": context_text,
        "evidence_map": evidence_map,
        "incident": incident,
        "evidence_items": evidence_items,
        "techniques": incident.techniques,
    }


def _format_context(
    incident: Incident,
    evidence_items: List[Evidence],
    evidence_map: Dict[str, str],
) -> str:
    """Format incident metadata and evidence records into structured XML within untrusted boundaries."""
    return serialize_untrusted_evidence(incident, evidence_items, evidence_map)


def format_chat_history(chat_history: Optional[List[Any]]) -> str:
    """Format recent conversation history into structured XML within untrusted boundaries."""
    return serialize_conversation_history(chat_history)


_format_chat_history = format_chat_history
