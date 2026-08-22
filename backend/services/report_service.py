"""
Report Service — assembles and renders incident reports.

Data preparation (grouping, consolidation) happens here in Python.
Jinja is responsible only for presentation/template rendering.
"""

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

    # ── Data preparation in Python (not Jinja) ──────────────────────
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


# ── Data preparation helpers ────────────────────────────────────────────────


def _build_template_timeline(hypothesis: Dict[str, Any]) -> List[Any]:
    """Convert hypothesis phases into simple objects for the Jinja template."""
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
    """Consolidate duplicate MITRE ATT&CK techniques.

    If both T1110 and T1110.001 exist, keep the more specific sub-technique
    and drop the parent if they share the same tactic.
    Never invent or alter technique data — only deduplicate.
    """
    if not techniques:
        return []

    # Group by base technique ID (e.g., T1110)
    by_base: Dict[str, list] = {}
    for t in techniques:
        base = t.technique_id
        by_base.setdefault(base, []).append(t)

    consolidated = []
    seen_keys: set = set()

    for base_id, group in by_base.items():
        # Separate parent techniques from sub-techniques
        parents = [t for t in group if not t.sub_technique_id]
        subs = [t for t in group if t.sub_technique_id]

        if subs:
            # Keep only the sub-techniques (more specific)
            for sub in subs:
                key = f"{sub.technique_id}|{sub.sub_technique_id}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    consolidated.append(sub)
        else:
            # No sub-techniques, keep the parent
            for parent in parents:
                key = parent.technique_id
                if key not in seen_keys:
                    seen_keys.add(key)
                    consolidated.append(parent)

    return consolidated


def _group_evidence(evidence_sorted: list) -> List[Any]:
    """Group consecutive evidence items with the same event_type.

    Returns a list of SimpleNamespace objects. Each has:
      - is_group (bool): True if this represents multiple events
      - items: list of original Evidence objects in the group
      - count: number of items
      - label: e.g. "EV-001"
      - label_range: e.g. "EV-002 → EV-008" (for groups)
      - event_type, source_ip, username, first_time, last_time, description
    """
    if not evidence_sorted:
        return []

    groups: List[Any] = []
    current_group: list = [evidence_sorted[0]]

    for ev in evidence_sorted[1:]:
        prev = current_group[-1]
        # Group if same event_type and same source_ip/user
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
    """Create a SimpleNamespace for a group of evidence items."""
    first = items[0]
    last = items[-1]

    first_idx = offset + 1  # we'll compute the real index based on overall position
    # Compute real 1-based indices from sequence_order
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
