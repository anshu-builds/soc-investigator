from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class EventType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    PRIV_CHANGE = "PRIV_CHANGE"
    FILE_ACCESS = "FILE_ACCESS"
    PROCESS_EXEC = "PROCESS_EXEC"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackPhase(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    COMPROMISE = "COMPROMISE"
    ESCALATION = "ESCALATION"
    IMPACT = "IMPACT"
    UNKNOWN = "UNKNOWN"


@dataclass
class NormalizedEvent:
    id: uuid.UUID
    timestamp: datetime
    event_type: EventType
    source_ip: str
    raw_log: str
    description: str
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class Alert:
    id: uuid.UUID
    rule_name: str
    severity: Severity
    confidence: float
    description: str
    contributing_event_ids: List[uuid.UUID]
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    attack_phase: AttackPhase = AttackPhase.UNKNOWN
