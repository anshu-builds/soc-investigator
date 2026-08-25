from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set

from detection import AttackPhase, EventType, NormalizedEvent


@dataclass
class TimelineEntry:
    sequence_order: int
    timestamp: datetime
    phase: AttackPhase
    event_id: uuid.UUID
    event_type: EventType
    source_ip: str
    username: Optional[str]
    hostname: Optional[str]
    description: str
    is_pivotal: bool
    raw_log: str


EVENT_PHASE_MAP: Dict[EventType, AttackPhase] = {
    EventType.AUTH_FAILURE: AttackPhase.INITIAL_ACCESS,
    EventType.AUTH_SUCCESS: AttackPhase.COMPROMISE,
    EventType.PRIV_CHANGE:  AttackPhase.ESCALATION,
    EventType.FILE_ACCESS:  AttackPhase.IMPACT,
    EventType.PROCESS_EXEC: AttackPhase.IMPACT,
    EventType.UNKNOWN:      AttackPhase.UNKNOWN,
}


def build_timeline(
    events: List[NormalizedEvent],
    incident_event_ids: Set[uuid.UUID],
) -> List[TimelineEntry]:
    incident_events = [e for e in events if e.id in incident_event_ids]
    incident_events.sort(key=lambda e: e.timestamp)

    entries: List[TimelineEntry] = []
    seen_phases: Set[AttackPhase] = set()
    failure_count = 0
    first_success_seen = False
    first_priv_seen = False

    for order, event in enumerate(incident_events, start=1):
        phase = EVENT_PHASE_MAP.get(event.event_type, AttackPhase.UNKNOWN)

        is_pivotal = False
        if event.event_type == EventType.AUTH_FAILURE:
            failure_count += 1
            if failure_count == 1:
                is_pivotal = True
        elif event.event_type == EventType.AUTH_SUCCESS and not first_success_seen:
            is_pivotal = True
            first_success_seen = True
        elif event.event_type == EventType.PRIV_CHANGE and not first_priv_seen:
            is_pivotal = True
            first_priv_seen = True
        elif phase not in seen_phases:
            is_pivotal = True

        seen_phases.add(phase)

        description = _generate_description(event, failure_count)

        entries.append(TimelineEntry(
            sequence_order=order,
            timestamp=event.timestamp,
            phase=phase,
            event_id=event.id,
            event_type=event.event_type,
            source_ip=event.source_ip,
            username=event.username,
            hostname=event.hostname,
            description=description,
            is_pivotal=is_pivotal,
            raw_log=event.raw_log,
        ))

    return entries


def _generate_description(event: NormalizedEvent, failure_count: int = 0) -> str:
    user = f"'{event.username}'" if event.username else "unknown user"
    src = event.source_ip

    if event.event_type == EventType.AUTH_FAILURE:
        return f"Failed login attempt #{failure_count} from {src} targeting {user}"
    elif event.event_type == EventType.AUTH_SUCCESS:
        return f"Successful authentication as {user} from {src}"
    elif event.event_type == EventType.PRIV_CHANGE:
        host = f" on {event.hostname}" if event.hostname else ""
        return f"Privilege escalation: {user} received elevated permissions{host}"
    elif event.event_type == EventType.FILE_ACCESS:
        path = event.metadata.get("file_path", "")
        return f"File access by {user}: {path}" if path else f"Sensitive file accessed by {user}"
    elif event.event_type == EventType.PROCESS_EXEC:
        proc = event.metadata.get("process_name", "")
        return f"Process executed by {user}: {proc}" if proc else f"Process execution by {user}"
    else:
        return event.description or f"Security event from {src}"
