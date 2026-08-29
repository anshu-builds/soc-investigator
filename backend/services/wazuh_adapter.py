"""Wazuh Alert → NormalizedEvent adapter.

Translates Wazuh Manager alert JSON into the existing ``NormalizedEvent``
dataclass so that alerts flow through the existing detection → correlation →
incident → AI → report pipeline unchanged.

EventType mapping uses a **semantic priority chain**:
  1. rule.groups keywords
  2. data-field signatures
  3. decoder.name patterns
  4. rule.description keyword fallback
  5. EventType.UNKNOWN

Rule IDs are preserved as provenance metadata, NOT used for classification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field, field_validator

from detection import EventType, NormalizedEvent

logger = logging.getLogger("soc.wazuh")

# ---------------------------------------------------------------------------
# Pydantic models for Wazuh alert payload validation
# ---------------------------------------------------------------------------


class WazuhRule(BaseModel):
    id: str = Field(..., min_length=1)
    level: int = Field(..., ge=0, le=16)
    description: str = ""
    groups: List[str] = Field(default_factory=list)
    mitre: Optional[Dict[str, Any]] = None


class WazuhAgent(BaseModel):
    id: str = ""
    name: str = ""
    ip: Optional[str] = None


class WazuhDecoder(BaseModel):
    name: str = ""


class WazuhAlert(BaseModel):
    """Validates a single Wazuh alert payload.

    Only ``rule``, ``agent``, and ``timestamp`` are required.  Every other
    field is optional and extracted defensively.
    """

    timestamp: str
    rule: WazuhRule
    agent: WazuhAgent
    decoder: Optional[WazuhDecoder] = None
    full_log: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("timestamp must not be empty")
        return v.strip()


class WazuhIngestionRequest(BaseModel):
    """Top-level request body for the webhook endpoint."""

    alerts: List[WazuhAlert] = Field(..., min_length=1, max_length=500)


class WazuhIngestionResponse(BaseModel):
    received: int
    processed: int
    duplicates: int
    errors: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP: List[Tuple[int, str]] = [
    (12, "CRITICAL"),
    (8, "HIGH"),
    (5, "MEDIUM"),
    (0, "LOW"),
]


def _map_severity(level: int) -> str:
    for threshold, severity in _SEVERITY_MAP:
        if level >= threshold:
            return severity
    return "LOW"


# ---------------------------------------------------------------------------
# Semantic EventType mapping
# ---------------------------------------------------------------------------

# Priority 1 — rule.groups keywords (case-insensitive set membership)
_GROUP_AUTH_FAILURE: Set[str] = {
    "authentication_failed",
    "login_failed",
    "invalid_login",
    "authentication_failures",
    "pam_auth",
}

_GROUP_AUTH_SUCCESS: Set[str] = {
    "authentication_success",
    "login_success",
    "session_opened",
}

_GROUP_PRIV_CHANGE: Set[str] = {
    "sudo",
    "su",
    "privilege",
    "priv_esc",
    "admin_access",
    "privilege_escalation",
}

_GROUP_FILE_ACCESS: Set[str] = {
    "syscheck",
    "file_integrity",
    "rootcheck",
}

_GROUP_PROCESS_EXEC: Set[str] = {
    "process",
    "command",
    "audit_command",
}


def _classify_by_groups(groups: List[str]) -> Optional[EventType]:
    """Priority 1: classify using rule.groups keywords."""
    lower_groups = {g.lower() for g in groups}

    if lower_groups & _GROUP_AUTH_FAILURE:
        return EventType.AUTH_FAILURE
    if lower_groups & _GROUP_AUTH_SUCCESS:
        return EventType.AUTH_SUCCESS
    if lower_groups & _GROUP_PRIV_CHANGE:
        return EventType.PRIV_CHANGE
    if lower_groups & _GROUP_FILE_ACCESS:
        return EventType.FILE_ACCESS
    if lower_groups & _GROUP_PROCESS_EXEC:
        return EventType.PROCESS_EXEC
    return None


def _classify_by_data(data: Optional[Dict[str, Any]]) -> Optional[EventType]:
    """Priority 2: classify using data-field signatures."""
    if not data:
        return None

    status = str(data.get("status", "")).lower()
    has_user = bool(data.get("srcuser") or data.get("dstuser") or data.get("user"))

    if has_user and status in ("failed", "invalid", "denied", "failure"):
        return EventType.AUTH_FAILURE
    if has_user and status in ("success", "accepted", "ok"):
        return EventType.AUTH_SUCCESS

    command = str(data.get("command", "")).lower()
    if command and ("sudo" in command or command == "su"):
        return EventType.PRIV_CHANGE

    if data.get("file") or data.get("path"):
        return EventType.FILE_ACCESS

    return None


def _classify_by_decoder(decoder_name: str) -> Optional[EventType]:
    """Priority 3: narrow classification hint from decoder name.

    Returns ``None`` when the decoder is ambiguous (e.g. ``sshd`` could be
    success or failure).  The caller should fall through to the next priority.
    """
    lower = decoder_name.lower()
    if "syscheck" in lower:
        return EventType.FILE_ACCESS
    # sshd / pam / auth decoders are ambiguous — do not classify here
    return None


# Keyword sets for rule.description fallback (priority 4).
# Reuses the same concepts as detection/normalizer.py but applied to Wazuh's
# rule.description field.
_DESC_AUTH_FAILURE_KW = {
    "authentication failure",
    "failed login",
    "login failed",
    "invalid password",
    "bad password",
    "incorrect password",
    "logon failure",
    "auth failed",
    "failed password",
    "user unknown",
    "authentication error",
}

_DESC_AUTH_SUCCESS_KW = {
    "authentication success",
    "login success",
    "user logged in",
    "session opened",
    "successful login",
    "accepted password",
    "successful authentication",
    "logon success",
}

_DESC_PRIV_CHANGE_KW = {
    "privilege escalation",
    "sudo",
    "elevated",
    "role change",
    "privilege assigned",
    "root access",
}

_DESC_FILE_ACCESS_KW = {
    "file access",
    "integrity check",
    "file modified",
    "file added",
    "file deleted",
    "checksum changed",
}

_DESC_PROCESS_EXEC_KW = {
    "process created",
    "new process",
    "process execution",
    "command execution",
}


def _classify_by_description(description: str) -> Optional[EventType]:
    """Priority 4: keyword scan on rule.description."""
    lower = description.lower()

    for kw in _DESC_AUTH_FAILURE_KW:
        if kw in lower:
            return EventType.AUTH_FAILURE
    for kw in _DESC_AUTH_SUCCESS_KW:
        if kw in lower:
            return EventType.AUTH_SUCCESS
    for kw in _DESC_PRIV_CHANGE_KW:
        if kw in lower:
            return EventType.PRIV_CHANGE
    for kw in _DESC_FILE_ACCESS_KW:
        if kw in lower:
            return EventType.FILE_ACCESS
    for kw in _DESC_PROCESS_EXEC_KW:
        if kw in lower:
            return EventType.PROCESS_EXEC
    return None


def map_event_type(alert: WazuhAlert) -> EventType:
    """Determine ``EventType`` using the semantic priority chain.

    1. rule.groups
    2. data field signatures
    3. decoder.name
    4. rule.description keywords
    5. ``EventType.UNKNOWN``
    """
    result = _classify_by_groups(alert.rule.groups)
    if result is not None:
        return result

    result = _classify_by_data(alert.data)
    if result is not None:
        return result

    if alert.decoder:
        result = _classify_by_decoder(alert.decoder.name)
        if result is not None:
            return result

    result = _classify_by_description(alert.rule.description)
    if result is not None:
        return result

    return EventType.UNKNOWN


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def _parse_timestamp(raw: str) -> datetime:
    """Parse Wazuh timestamp (ISO 8601 variants)."""
    raw = raw.strip()
    try:
        iso_raw = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        logger.warning("Failed to parse Wazuh timestamp %r, using now()", raw)
        return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def compute_dedup_hash(alert: WazuhAlert) -> str:
    """SHA-256 hash for idempotency check.

    Key components: agent_id + rule_id + timestamp + first 256 chars of
    full_log.
    """
    parts = [
        alert.agent.id,
        alert.rule.id,
        alert.timestamp,
        (alert.full_log or "")[:256],
    ]
    payload = "|".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Core normalizer
# ---------------------------------------------------------------------------

def normalize_wazuh_alert(alert: WazuhAlert) -> NormalizedEvent:
    """Convert a validated ``WazuhAlert`` into a ``NormalizedEvent``.

    The returned event carries full Wazuh provenance in ``metadata`` and is
    compatible with the existing detection → correlation → incident pipeline.
    """
    data = alert.data or {}

    # --- field extraction with fallbacks ---
    source_ip = (
        data.get("srcip")
        or (alert.agent.ip if alert.agent.ip else None)
        or "0.0.0.0"
    )

    username = (
        data.get("srcuser")
        or data.get("dstuser")
        or data.get("user")
        or None
    )

    destination_ip = data.get("dstip") or None
    hostname = alert.agent.name or None
    description = alert.rule.description or ""

    # Prefer full_log; fall back to serialized alert
    raw_log = alert.full_log or json.dumps(
        alert.model_dump(mode="python"), default=str
    )

    timestamp = _parse_timestamp(alert.timestamp)
    event_type = map_event_type(alert)
    severity = _map_severity(alert.rule.level)

    # --- provenance metadata ---
    metadata: Dict[str, Any] = {
        # Source identification
        "source_type": "wazuh",
        "source_file": f"wazuh://agent/{alert.agent.name or 'unknown'}/rule/{alert.rule.id}",

        # Wazuh rule provenance
        "wazuh_rule_id": alert.rule.id,
        "wazuh_rule_level": alert.rule.level,
        "wazuh_rule_description": alert.rule.description,
        "wazuh_rule_groups": alert.rule.groups,

        # Agent provenance
        "wazuh_agent_id": alert.agent.id,
        "wazuh_agent_name": alert.agent.name,

        # Decoder provenance
        "wazuh_decoder": alert.decoder.name if alert.decoder else "",

        # MITRE metadata (when available)
        "wazuh_mitre": alert.rule.mitre,

        # Severity provenance
        "severity_raw": severity,

        # Raw event preservation (complete original alert)
        "wazuh_raw": alert.model_dump(mode="python"),
    }

    return NormalizedEvent(
        id=uuid.uuid4(),
        timestamp=timestamp,
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        hostname=hostname,
        description=description,
        raw_log=raw_log,
        metadata=metadata,
    )


def normalize_wazuh_alerts(alerts: List[WazuhAlert]) -> List[NormalizedEvent]:
    """Normalize a batch of Wazuh alerts."""
    return [normalize_wazuh_alert(a) for a in alerts]
