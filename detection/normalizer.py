from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from detection import EventType, NormalizedEvent

TIMESTAMP_FIELDS = ["timestamp", "@timestamp", "event_time", "time", "date_time", "datetime"]
SOURCE_IP_FIELDS = ["src_ip", "source_ip", "sourceIp", "src", "source_address", "client_ip"]
USERNAME_FIELDS  = ["user", "username", "account", "user_name", "user_id", "login"]
HOSTNAME_FIELDS  = ["host", "hostname", "computer", "device", "machine", "server"]
DEST_IP_FIELDS   = ["dst_ip", "destination_ip", "dest_ip", "dst", "target_ip"]
DESCRIPTION_FIELDS = ["message", "description", "msg", "detail", "event_message", "log_message"]
EVENT_TYPE_FIELDS  = ["event_type", "action", "event_id", "type", "event_name", "event"]

AUTH_FAILURE_KEYWORDS = {
    "FAILED_LOGIN", "4625", "authentication failure", "invalid password",
    "login failed", "auth_failure", "logon failure", "authentication_failure",
    "bad password", "wrong password", "incorrect password", "login_failure",
    "failed_authentication", "auth failed",
}

AUTH_SUCCESS_KEYWORDS = {
    "SUCCESSFUL_LOGIN", "4624", "authentication success", "user logged in",
    "login success", "auth_success", "logon success", "authentication_success",
    "logged in", "successful logon", "login_success", "auth_successful",
}

PRIV_CHANGE_KEYWORDS = {
    "4672", "privilege assigned", "sudo", "elevated", "role change",
    "privilege escalation", "priv_change", "privilege_change", "su",
    "admin privileges", "root access", "privilege_escalation", "priv_escalation",
    "role_change", "privilege granted", "elevated privileges",
}

FILE_ACCESS_KEYWORDS = {
    "FILE_READ", "file_access", "4663", "file access", "file_read",
    "file_write", "file_delete", "file_modify", "read_file", "open_file",
}

PROCESS_EXEC_KEYWORDS = {
    "PROCESS_CREATE", "4688", "process_execution", "process created",
    "new process", "process_exec", "cmd execution", "command execution",
}


def _resolve_field(row: Dict[str, Any], candidates: List[str]) -> Optional[str]:
    for key in candidates:
        val = row.get(key) or row.get(key.lower()) or row.get(key.upper())
        if val is not None and str(val).strip():
            return str(val).strip()
    return None


def _parse_timestamp(raw: Optional[str]) -> datetime:
    if not raw:
        return datetime.now(tz=timezone.utc)

    raw = raw.strip()

    try:
        iso_raw = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_raw)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except ValueError:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    try:
        ts = float(raw)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        pass

    return datetime.now(tz=timezone.utc)


def _map_event_type(raw_type: Optional[str]) -> EventType:
    if not raw_type:
        return EventType.UNKNOWN

    normalized = raw_type.strip().lower()

    for kw in AUTH_FAILURE_KEYWORDS:
        if kw.lower() == normalized or kw.lower() in normalized:
            return EventType.AUTH_FAILURE

    for kw in AUTH_SUCCESS_KEYWORDS:
        if kw.lower() == normalized or kw.lower() in normalized:
            return EventType.AUTH_SUCCESS

    for kw in PRIV_CHANGE_KEYWORDS:
        if kw.lower() == normalized or kw.lower() in normalized:
            return EventType.PRIV_CHANGE

    for kw in FILE_ACCESS_KEYWORDS:
        if kw.lower() == normalized or kw.lower() in normalized:
            return EventType.FILE_ACCESS

    for kw in PROCESS_EXEC_KEYWORDS:
        if kw.lower() == normalized or kw.lower() in normalized:
            return EventType.PROCESS_EXEC

    return EventType.UNKNOWN


def normalize_row(row: Dict[str, Any], source_file: str = "") -> Optional[NormalizedEvent]:
    raw_timestamp = _resolve_field(row, TIMESTAMP_FIELDS)
    raw_event_type = _resolve_field(row, EVENT_TYPE_FIELDS)
    source_ip = _resolve_field(row, SOURCE_IP_FIELDS) or "0.0.0.0"
    username = _resolve_field(row, USERNAME_FIELDS)
    hostname = _resolve_field(row, HOSTNAME_FIELDS)
    dest_ip = _resolve_field(row, DEST_IP_FIELDS)
    description = _resolve_field(row, DESCRIPTION_FIELDS) or ""

    timestamp = _parse_timestamp(raw_timestamp)
    event_type = _map_event_type(raw_event_type)

    raw_log = " | ".join(f"{k}={v}" for k, v in row.items() if v is not None)

    known_keys = set(
        TIMESTAMP_FIELDS + SOURCE_IP_FIELDS + USERNAME_FIELDS +
        HOSTNAME_FIELDS + DEST_IP_FIELDS + DESCRIPTION_FIELDS + EVENT_TYPE_FIELDS
    )
    extra_metadata = {k: v for k, v in row.items() if k not in known_keys and v is not None}
    if source_file:
        extra_metadata["source_file"] = source_file

    return NormalizedEvent(
        id=uuid.uuid4(),
        timestamp=timestamp,
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=dest_ip,
        username=username,
        hostname=hostname,
        description=description,
        raw_log=raw_log,
        metadata=extra_metadata,
    )


def normalize_batch(rows: List[Dict[str, Any]], source_file: str = "") -> List[NormalizedEvent]:
    events = []
    for row in rows:
        event = normalize_row(row, source_file)
        if event is not None:
            events.append(event)
    return events
