"""
AI Context Builder

Pulls incident + evidence + attack_hypothesis from the DB and formats
a structured context string for the LLM. No raw logs in context —
only formatted, human-readable summaries of events.
"""

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
    """
    Build a structured context dict for the LLM.

    Returns:
        {
            "context_text": str,       # Formatted text for the LLM prompt
            "evidence_map": dict,      # EV-short-id → evidence UUID (for citation validation)
            "incident": Incident,
            "evidence_items": list,
            "techniques": list,
        }
    """
    # Load incident with related data
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

    # Build evidence map: EV-001 → real UUID
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
    """Format incident data as structured text (not raw logs)."""
    lines: List[str] = []

    # Header
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

    # Attack hypothesis
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

    # MITRE techniques
    if incident.techniques:
        lines.append("MITRE ATT&CK TECHNIQUES:")
        for tech in incident.techniques:
            sub = f" > {tech.sub_technique_name}" if tech.sub_technique_name else ""
            lines.append(
                f"  • {tech.technique_id}{sub}: {tech.technique_name} "
                f"(Tactic: {tech.tactic})"
            )
        lines.append("")

    # Evidence list
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
