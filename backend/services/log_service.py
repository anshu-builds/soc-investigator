from __future__ import annotations

import csv
import io
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.models import Evidence, Incident, AttackTechnique, SecurityEvent
from correlation.correlator import IncidentGroup, correlate
from correlation.hypothesis import build_hypothesis
from correlation.mitre_mapper import map_techniques
from correlation.timeline_builder import TimelineEntry, build_timeline
from detection import NormalizedEvent
from detection.engine import DetectionEngine
from detection.normalizer import normalize_batch


EVENT_CATEGORY_MAP = {
    "AUTH_FAILURE": "authentication",
    "AUTH_SUCCESS": "authentication",
    "PRIV_CHANGE":  "authorization",
    "FILE_ACCESS":  "file_system",
    "PROCESS_EXEC": "process",
    "UNKNOWN":      "unknown",
}


def parse_upload(content: bytes, filename: str) -> List[Dict[str, Any]]:
    text = content.decode("utf-8-sig", errors="replace")  # Handle BOM
    fn_lower = filename.lower()

    if fn_lower.endswith(".json"):
        data = json.loads(text)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "events" in data:
            return data["events"]
        return [data]
    else:
        reader = csv.DictReader(io.StringIO(text))
        return [row for row in reader]


async def run_pipeline(
    db: AsyncSession,
    raw_rows: List[Dict[str, Any]],
    source_file: str,
    *,
    _pre_normalized: Optional[List[NormalizedEvent]] = None,
) -> Tuple[int, int, int]:
    normalized: List[NormalizedEvent] = (
        _pre_normalized if _pre_normalized is not None
        else normalize_batch(raw_rows, source_file)
    )
    if not normalized:
        return 0, 0, 0

    db_events = await _persist_events(db, normalized)
    await db.flush()

    engine = DetectionEngine()
    alerts = engine.run(normalized)

    if not alerts:
        return len(normalized), 0, 0

    flagged_ids = set()
    for alert in alerts:
        for eid in alert.contributing_event_ids:
            flagged_ids.add(eid)

    flagged_count = len(flagged_ids)
    for event in db_events:
        if event.id in flagged_ids:
            event.is_flagged = True

    groups: List[IncidentGroup] = correlate(alerts, normalized)

    incidents_created = 0
    event_id_map: Dict[uuid.UUID, SecurityEvent] = {e.id: e for e in db_events}

    for group in groups:
        group_event_ids = set(group.all_event_ids)
        timeline: List[TimelineEntry] = build_timeline(normalized, group_event_ids)

        hypothesis = build_hypothesis(group, timeline)
        attack_type = hypothesis["classification"]

        title = _make_incident_title(attack_type, group)

        incident = Incident(
            id=uuid.uuid4(),
            title=title,
            description=hypothesis.get("narrative", ""),
            attack_type=attack_type,
            severity=group.overall_severity.value,
            confidence=group.overall_confidence,
            status="OPEN",
            affected_username=group.username,
            source_ip=group.source_ip,
            affected_host=group.hostname,
            first_seen=group.first_seen or datetime.now(timezone.utc),
            last_seen=group.last_seen or datetime.now(timezone.utc),
            event_count=len(group.all_event_ids),
            attack_hypothesis=hypothesis,
        )
        db.add(incident)
        await db.flush()

        for entry in timeline:
            db_event = event_id_map.get(entry.event_id)
            if db_event is None:
                continue

            db_event.incident_id = incident.id

            role = _determine_evidence_role(entry)
            evidence = Evidence(
                incident_id=incident.id,
                event_id=entry.event_id,
                role=role,
                description=entry.description,
                sequence_order=entry.sequence_order,
            )
            db.add(evidence)

        techniques = map_techniques(attack_type)
        for tech in techniques:
            at = AttackTechnique(
                incident_id=incident.id,
                technique_id=tech["technique_id"],
                technique_name=tech["technique_name"],
                tactic=tech["tactic"],
                sub_technique_id=tech.get("sub_technique_id"),
                sub_technique_name=tech.get("sub_technique_name"),
                confidence=tech["confidence"],
                mapping_source=tech["mapping_source"],
                url=tech.get("url"),
            )
            db.add(at)

        incidents_created += 1

    await db.flush()
    return len(normalized), flagged_count, incidents_created


async def _persist_events(
    db: AsyncSession,
    normalized: List[NormalizedEvent],
) -> List[SecurityEvent]:
    db_events = []
    for event in normalized:
        category = EVENT_CATEGORY_MAP.get(event.event_type.value, "unknown")
        db_event = SecurityEvent(
            id=event.id,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            username=event.username,
            hostname=event.hostname,
            event_type=event.event_type.value,
            event_category=category,
            timestamp=event.timestamp,
            description=event.description,
            raw_log=event.raw_log,
            source_file=event.metadata.get("source_file", ""),
            is_flagged=False,
            extra_metadata=event.metadata or {},
        )
        db.add(db_event)
        db_events.append(db_event)
    return db_events


def _make_incident_title(attack_type: str, group: IncidentGroup) -> str:
    user = group.username or "unknown user"
    ip = group.source_ip or "unknown IP"
    titles = {
        "BRUTE_FORCE": f"Brute Force Attack against '{user}' from {ip}",
        "ACCOUNT_COMPROMISE": f"Account Compromise: '{user}' accessed from {ip}",
        "ACCOUNT_COMPROMISE_WITH_ESCALATION": f"Account Compromise + Privilege Escalation: '{user}'",
        "PRIVILEGE_ESCALATION": f"Privilege Escalation detected for '{user}'",
    }
    return titles.get(attack_type, f"Security Incident: {attack_type}")


def _determine_evidence_role(entry: TimelineEntry) -> str:
    from detection import AttackPhase, EventType
    if entry.event_type == EventType.AUTH_SUCCESS:
        return "COMPROMISE_INDICATOR"
    elif entry.event_type == EventType.PRIV_CHANGE:
        return "ANOMALOUS_BEHAVIOR"
    elif entry.is_pivotal:
        return "TRIGGER_EVENT"
    else:
        return "SUPPORTING_EVENT"
