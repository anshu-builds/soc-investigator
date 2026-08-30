from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from detection import Alert, AttackPhase, EventType, NormalizedEvent, Severity
from detection.rules import BaseRule

SENSITIVE_PATH_PATTERNS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "\\system32", "\\SAM", "\\SECURITY",
    "/root/", "/var/log/auth",
    "C:\\Windows\\System32",
]


class PrivilegeEscalationRule(BaseRule):
    def __init__(
        self,
        success_to_priv_window_minutes: int = 30,
        require_context: bool = True,
    ):
        self.success_to_priv_window_minutes = success_to_priv_window_minutes
        self.require_context = require_context

    @property
    def rule_name(self) -> str:
        return "PRIVILEGE_ESCALATION"

    def evaluate(
        self,
        events: List[NormalizedEvent],
        indexed: Dict[Tuple, List[NormalizedEvent]],
    ) -> List[Alert]:
        alerts: List[Alert] = []

        by_user: Dict[Optional[str], List[NormalizedEvent]] = defaultdict(list)
        for event in events:
            by_user[event.username].append(event)

        window = timedelta(
            minutes=self.success_to_priv_window_minutes
        )

        for username, user_events in by_user.items():
            if not username:
                continue

            sorted_events = sorted(
                user_events,
                key=lambda e: e.timestamp
            )

            auth_successes = [
                e for e in sorted_events
                if e.event_type == EventType.AUTH_SUCCESS
            ]
            priv_changes   = [
                e for e in sorted_events
                if e.event_type == EventType.PRIV_CHANGE
            ]
            file_accesses  = [
                e for e in sorted_events
                if e.event_type == EventType.FILE_ACCESS
            ]

            if not priv_changes:
                continue

            first_priv = priv_changes[0]

            preceding_success = [
                s for s in auth_successes
                if s.timestamp <= first_priv.timestamp
                and (
                    first_priv.timestamp - s.timestamp
                ) <= window
            ]

            trigger_success = (
                preceding_success[-1]
                if preceding_success
                else None
            )

            post_priv_file_accesses = [
                f for f in file_accesses
                if f.timestamp >= first_priv.timestamp
                and self._is_sensitive_path(f)
            ]

            has_recent_success = bool(preceding_success)
            has_sensitive_access = bool(
                post_priv_file_accesses
            )

            if self.require_context:
                is_benign_context = (
                    has_recent_success
                    and not has_sensitive_access
                )

                if is_benign_context:
                    continue

            confidence = self._calculate_confidence(
                first_priv,
                preceding_success,
                post_priv_file_accesses
            )
            if has_sensitive_access:
                severity = Severity.CRITICAL
            else:
                severity = Severity.HIGH

            contributing_ids = (
                [s.id for s in preceding_success]
                + [p.id for p in priv_changes]
                + [f.id for f in post_priv_file_accesses]
            )

            sensitive_paths = [
                f.metadata.get("file_path", "") for f in post_priv_file_accesses
                if f.metadata.get("file_path")
            ]

            if trigger_success:
                description = (
                    f"Privilege escalation: user '{username}' received elevated privileges "
                    f"at {first_priv.timestamp.strftime('%H:%M:%S UTC')} following login "
                    f"at {trigger_success.timestamp.strftime('%H:%M:%S UTC')}"
                    + (f" — accessed sensitive paths: {', '.join(sensitive_paths)}" if sensitive_paths else "")
                )
            else:
                description = (
                    f"Privilege escalation: user '{username}' received elevated privileges "
                    f"at {first_priv.timestamp.strftime('%H:%M:%S UTC')} without recent login"
                    + (f" — accessed sensitive paths: {', '.join(sensitive_paths)}" if sensitive_paths else "")
                )

            metadata = {
                "username": username,
                "priv_change_event_id": str(first_priv.id),
                "priv_change_timestamp": first_priv.timestamp.isoformat(),
                "preceding_success_count": len(preceding_success),
                "sensitive_file_accesses": len(post_priv_file_accesses),
                "sensitive_paths": sensitive_paths,
            }

            if trigger_success:
                metadata["auth_event_id"] = str(trigger_success.id)

            alerts.append(Alert(
                id=uuid.uuid4(),
                rule_name=self.rule_name,
                severity=severity,
                confidence=confidence,
                description=description,
                contributing_event_ids=contributing_ids,
                metadata=metadata,
                attack_phase=AttackPhase.ESCALATION,
            ))

        return alerts

    def _is_sensitive_path(self, event: NormalizedEvent) -> bool:
        file_path = event.metadata.get("file_path", "") or event.description
        return any(pattern.lower() in file_path.lower() for pattern in SENSITIVE_PATH_PATTERNS)

    def _calculate_confidence(
        self,
        priv_event: NormalizedEvent,
        preceding_successes: List[NormalizedEvent],
        sensitive_accesses: List[NormalizedEvent],
    ) -> float:
        confidence = 0.65

    # Unexpected privilege change is suspicious.
        if not preceding_successes:
            confidence += 0.10

    # Sensitive activity after privilege escalation
    # provides stronger evidence.
        if sensitive_accesses:
            confidence += 0.20

        return min(confidence, 0.92)
