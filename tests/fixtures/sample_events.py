"""
Test Fixtures: Sample Events
"""

import uuid
from datetime import datetime, timedelta, timezone

from detection import NormalizedEvent, EventType


def generate_event(
    event_type: EventType,
    offset_minutes: int,
    source_ip: str = "10.0.0.5",
    username: str = "admin",
    base_time: datetime | None = None,
) -> NormalizedEvent:
    if base_time is None:
        base_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        
    return NormalizedEvent(
        id=uuid.uuid4(),
        timestamp=base_time + timedelta(minutes=offset_minutes),
        event_type=event_type,
        source_ip=source_ip,
        username=username,
        raw_log=event_type.value,
        description=event_type.value,
    )
