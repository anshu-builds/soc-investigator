"""
Report Service — assembles and renders incident reports.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.models import Evidence, Incident, Report


TEMPLATE_DIR = Path(__file__).parent.parent.parent / "reports" / "templates"

_jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=["html"]),
)


async def generate_report(
    db: AsyncSession,
    incident_id: uuid.UUID,
    format: str = "MARKDOWN",
    ai_summary: Optional[str] = None,
) -> Report:
    """Generate and persist a report for an incident."""
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
        raise ValueError(f"Incident {incident_id} not found")

    hypothesis = incident.attack_hypothesis or {}
    narrative = hypothesis.get("narrative", incident.description or "")

    # Build timeline entries from hypothesis phases for the template
    timeline_entries = _build_template_timeline(hypothesis)

    # Build recommended actions
    recommended = _build_recommended_actions(incident.attack_type)

    evidence_sorted = sorted(
        incident.evidence,
        key=lambda e: (e.sequence_order or 999, str(e.id)),
    )

    template = _jinja_env.get_template("incident_report.md.jinja")
    content = template.render(
        incident=incident,
        report_generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        narrative=narrative,
        ai_summary=ai_summary,
        techniques=incident.techniques,
        timeline=timeline_entries,
        evidence=evidence_sorted,
        recommended_actions=recommended,
    )

    report = Report(
        incident_id=incident.id,
        format=format,
        content=content,
        ai_summary=ai_summary,
        recommended_actions=recommended,
    )
    db.add(report)
    await db.flush()
    return report


def _build_template_timeline(hypothesis: Dict[str, Any]) -> List[Any]:
    """Convert hypothesis phases into simple objects for the Jinja template."""
    from types import SimpleNamespace
    from datetime import datetime, timezone
    entries = []
    for i, phase in enumerate(hypothesis.get("phases", []), 1):
        ts_raw = phase.get("timestamp_start", "")
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)
        entries.append(SimpleNamespace(
            sequence_order=i,
            timestamp=ts,
            phase=phase.get("phase", ""),
            event_type=phase.get("technique", ""),
            description=phase.get("description", ""),
        ))
    return entries


def _build_recommended_actions(attack_type: str) -> List[str]:
    base = [
        "Block the attacking source IP at the perimeter firewall.",
        "Reset credentials and enforce MFA for all affected accounts.",
        "Review authentication logs for the 24-hour window around the incident.",
        "Notify the affected account owner and confirm unauthorized access.",
        "Preserve all relevant logs for forensic investigation.",
    ]
    if "ESCALATION" in attack_type:
        base.insert(2, "Revoke all elevated privileges assigned during the incident window.")
        base.insert(3, "Isolate the affected host and perform memory forensics if possible.")
    if "COMPROMISE" in attack_type:
        base.insert(1, "Invalidate all active sessions and tokens for the compromised account.")
    return base
