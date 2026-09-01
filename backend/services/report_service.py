from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.models import Evidence, Incident, Report
from backend.security import (
    render_report_to_html,
    sanitize_code_block,
    sanitize_markdown_prose,
    sanitize_table_cell,
    sanitize_text,
)

TEMPLATE_DIR = Path(__file__).parent.parent.parent / "reports" / "templates"

_jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=False,
)
_jinja_env.filters["sanitize_text"] = sanitize_text
_jinja_env.filters["sanitize_cell"] = sanitize_table_cell
_jinja_env.filters["sanitize_code"] = sanitize_code_block
_jinja_env.filters["sanitize_markdown"] = sanitize_markdown_prose


async def generate_report(
    db: AsyncSession,
    incident_id: uuid.UUID,
    format: str = "MARKDOWN",
    ai_summary: Optional[str] = None,
) -> Report:
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

    timeline_entries = _build_template_timeline(hypothesis)
    recommended = _build_recommended_actions(incident.attack_type)
    consolidated_techniques = _consolidate_techniques(list(incident.techniques))

    evidence_sorted = sorted(
        incident.evidence,
        key=lambda e: (e.sequence_order or 999, str(e.id)),
    )
    evidence_groups = _group_evidence(evidence_sorted)

    template = _jinja_env.get_template("incident_report.md.jinja")
    content = template.render(
        incident=incident,
        report_generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        narrative=narrative,
        ai_summary=ai_summary,
        techniques=consolidated_techniques,
        timeline=timeline_entries,
        evidence_groups=evidence_groups,
        recommended_actions=recommended,
    )

    fmt = format.upper() if format else "MARKDOWN"
    if fmt == "HTML":
        rendered_content = render_report_to_html(content)
    else:
        rendered_content = content

    report = Report(
        incident_id=incident.id,
        format=fmt,
        content=rendered_content,
        ai_summary=ai_summary,
        recommended_actions=recommended,
    )
    db.add(report)
    await db.flush()
    return report


def _build_template_timeline(hypothesis: Dict[str, Any]) -> List[Any]:
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


def _consolidate_techniques(techniques: list) -> List[Any]:
    if not techniques:
        return []

    by_base: Dict[str, list] = {}
    for t in techniques:
        base = t.technique_id
        by_base.setdefault(base, []).append(t)

    consolidated = []
    seen_keys: set = set()

    for base_id, group in by_base.items():
        parents = [t for t in group if not t.sub_technique_id]
        subs = [t for t in group if t.sub_technique_id]

        if subs:
            for sub in subs:
                key = f"{sub.technique_id}|{sub.sub_technique_id}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    consolidated.append(sub)
        else:
            for parent in parents:
                key = parent.technique_id
                if key not in seen_keys:
                    seen_keys.add(key)
                    consolidated.append(parent)

    return consolidated


def _group_evidence(evidence_sorted: list) -> List[Any]:
    if not evidence_sorted:
        return []

    groups: List[Any] = []
    current_group: list = [evidence_sorted[0]]

    for ev in evidence_sorted[1:]:
        prev = current_group[-1]
        if (ev.event and prev.event
                and ev.event.event_type == prev.event.event_type
                and ev.event.source_ip == prev.event.source_ip
                and ev.event.username == prev.event.username):
            current_group.append(ev)
        else:
            groups.append(_finalize_group(current_group, len(groups)))
            current_group = [ev]

    groups.append(_finalize_group(current_group, len(groups)))
    return groups


def _finalize_group(items: list, offset: int) -> Any:
    first = items[0]
    last = items[-1]

    indices = []
    for i, item in enumerate(items):
        idx = item.sequence_order if item.sequence_order else (offset + i + 1)
        indices.append(idx)

    first_label = f"EV-{indices[0]:03d}"
    if len(items) == 1:
        label_range = first_label
    else:
        last_label = f"EV-{indices[-1]:03d}"
        label_range = f"{first_label} → {last_label}"

    ev = first.event
    return SimpleNamespace(
        is_group=len(items) > 1,
        items=items,
        count=len(items),
        label=first_label,
        label_range=label_range,
        event_type=ev.event_type if ev else "UNKNOWN",
        source_ip=ev.source_ip if ev else "N/A",
        username=ev.username or "N/A" if ev else "N/A",
        first_time=ev.timestamp if ev else None,
        last_time=last.event.timestamp if last.event else None,
        description=first.description or (ev.description if ev else ""),
        role=first.role,
        raw_log_sample=ev.raw_log[:300] if ev and ev.raw_log else "",
    )


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
