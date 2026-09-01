"""Centralized persistent security audit logging service.

Records non-repudiable audit trails for authentication attempts, incident status
transitions, investigation sessions, report generation, and administrative operations.
Guarantees sensitive credentials (passwords, tokens, API keys) are never stored in audit logs.
"""

from __future__ import annotations

import inspect
import logging
import re
import uuid
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from backend.models import AuditLog

logger = logging.getLogger("soc.security.audit")

# Keys that must never be recorded in audit log payloads
REDACTED_KEYS = {
    "password", "password_hash", "token", "access_token", "refresh_token",
    "jwt", "secret", "api_key", "key", "authorization", "cookie",
    "credential", "credentials", "x-wazuh-token", "wazuh_api_password",
}


def sanitize_audit_payload(data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Recursively redacts sensitive credentials from dictionary payloads."""
    if not data or not isinstance(data, dict):
        return data

    sanitized: Dict[str, Any] = {}
    for k, v in data.items():
        k_lower = str(k).lower()
        if any(red in k_lower for red in REDACTED_KEYS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_audit_payload(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_audit_payload(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


async def log_audit_event(
    db: Optional[AsyncSession],
    action: str,
    entity_type: str,
    *,
    actor_user_id: Optional[uuid.UUID] = None,
    entity_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    previous_state: Optional[Dict[str, Any]] = None,
    new_state: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None,
    status: str = "SUCCESS",
) -> Optional[AuditLog]:
    """Creates and enqueues an append-only AuditLog record in the current transaction."""
    if db is None:
        return None

    clean_prev = sanitize_audit_payload(previous_state)
    clean_new = sanitize_audit_payload(new_state)
    clean_details = sanitize_audit_payload(details)

    audit_entry = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        source_ip=source_ip[:45] if source_ip else None,
        user_agent=user_agent[:500] if user_agent else None,
        previous_state=clean_prev,
        new_state=clean_new,
        details=clean_details,
        status=status,
    )
    res = db.add(audit_entry)
    if inspect.isawaitable(res):
        await res
    return audit_entry
