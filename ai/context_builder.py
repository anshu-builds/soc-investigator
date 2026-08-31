from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.models import Evidence, Incident, AttackTechnique


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
    lines: List[str] = []

    lines.append(f"INCIDENT: {incident.title}")
    lines.append(
        f"SEVERITY: {incident.severity} | "
        f"CONFIDENCE: {incident.confidence:.0%} | "
        f"STATUS: {incident.status}"
    )
    if incident.affected_username:
        lines.append(f"AFFECTED USER: {incident.affected_username}")
    if incident.source_ip:
        lines.append(f"ATTACKING SOURCE IP: {incident.source_ip}")
    if incident.first_seen and incident.last_seen:
        lines.append(
            f"TIMEFRAME: {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} "
            f"to {incident.last_seen.strftime('%H:%M:%S UTC')}"
        )
    lines.append(f"TOTAL EVENTS: {incident.event_count}")
    lines.append("")

    hypothesis = incident.attack_hypothesis
    if hypothesis:
        lines.append("ATTACK NARRATIVE:")
        lines.append(hypothesis.get("narrative", ""))
        lines.append("")

        phases = hypothesis.get("phases", [])
        if phases:
            lines.append("ATTACK PHASES:")
            for i, phase in enumerate(phases, 1):
                ts_start = phase.get("timestamp_start", "")[:19].replace("T", " ")
                lines.append(
                    f"  {i}. {phase.get('phase')} ({ts_start}): "
                    f"{phase.get('description')} "
                    f"[{phase.get('technique')}]"
                )
            lines.append("")

    if incident.techniques:
        lines.append("MITRE ATT&CK TECHNIQUES:")
        for tech in incident.techniques:
            sub = f" > {tech.sub_technique_name}" if tech.sub_technique_name else ""
            lines.append(
                f"  • {tech.technique_id}{sub}: {tech.technique_name} "
                f"(Tactic: {tech.tactic})"
            )
        lines.append("")

    reverse_map = {v: k for k, v in evidence_map.items()}
    lines.append("EVIDENCE LIST (cite using [EV-NNN]):")
    for ev in evidence_items:
        short_id = reverse_map.get(str(ev.id), "EV-???")
        event = ev.event
        if event is None:
            continue
        ts = event.timestamp.strftime("%H:%M:%S UTC")
        lines.append(
            f"  [{short_id}] {ts} | {event.event_type:15s} | "
            f"src:{event.source_ip:17s} | "
            f"user:{event.username or 'N/A':20s} | "
            f"role:{ev.role:25s} | "
            f"{event.description or ''}"
        )

    return "\n".join(lines)


def format_chat_history(chat_history: Optional[List[Any]]) -> str:
    """Format recent conversation history into a structured text block.

    Treats history as conversational dialogue context, clearly distinguishing
    user inquiries from assistant responses.
    """
    if not chat_history:
        return ""

    lines: List[str] = []
    for msg in chat_history:
        if isinstance(msg, dict):
            role = str(msg.get("role", "unknown")).upper()
            content = str(msg.get("content") or "").strip()
        else:
            role = str(getattr(msg, "role", "unknown")).upper()
            content = str(getattr(msg, "content", "") or "").strip()

        if not content:
            continue

        if role in ("USER", "HUMAN", "ANALYST"):
            lines.append(f"Analyst: {content}")
        elif role in ("ASSISTANT", "AI", "SYSTEM"):
            lines.append(f"Assistant: {content}")
        else:
            lines.append(f"{role.capitalize()}: {content}")

    return "\n\n".join(lines)


_format_chat_history = format_chat_history
