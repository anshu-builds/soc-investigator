"""
Correlation Engine

Groups related Alerts into IncidentGroups by shared (username OR source_ip)
within a configurable time window.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Set, Dict

from detection import Alert, Severity, NormalizedEvent


CORRELATION_WINDOW_MINUTES = 60  # Alerts within 60 minutes are grouped


@dataclass
class IncidentGroup:
    """A group of correlated alerts that form one attack incident."""
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    alerts: List[Alert] = field(default_factory=list)

    # Primary correlation entities
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None

    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # All event IDs contributing to this incident (union across all alerts)
    all_event_ids: List[uuid.UUID] = field(default_factory=list)

    def add_alert(self, alert: Alert, alert_ts: datetime) -> None:
        self.alerts.append(alert)
        self._update_timestamps(alert_ts)
        self._merge_event_ids(alert)

    def _update_timestamps(self, ts: datetime) -> None:
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    def _merge_event_ids(self, alert: Alert) -> None:
        existing: Set[uuid.UUID] = set(self.all_event_ids)
        for eid in alert.contributing_event_ids:
            if eid not in existing:
                self.all_event_ids.append(eid)
                existing.add(eid)

    @property
    def overall_severity(self) -> Severity:
        """Highest severity across all alerts in this group."""
        order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
        return max(self.alerts, key=lambda a: order.get(a.severity, 0)).severity

    @property
    def overall_confidence(self) -> float:
        """Weighted average confidence: trigger alerts (1.0) vs supporting (0.8)."""
        if not self.alerts:
            return 0.0
        total_weight = 0.0
        weighted_sum = 0.0
        for i, alert in enumerate(sorted(self.alerts, key=lambda a: getattr(a, "_event_ts", a.detected_at))):
            weight = 1.0 if i == 0 else 0.8
            weighted_sum += alert.confidence * weight
            total_weight += weight

        confidence = weighted_sum / total_weight
        # Bonus for logical phase progression
        phases = [a.attack_phase.value for a in self.alerts]
        ideal_sequence = ["INITIAL_ACCESS", "COMPROMISE", "ESCALATION", "IMPACT"]
        if self._is_ordered_subsequence(phases, ideal_sequence):
            confidence = min(confidence + 0.05, 0.98)
        return round(confidence, 3)

    def _is_ordered_subsequence(self, sequence: List[str], ideal: List[str]) -> bool:
        """Check if 'sequence' appears in the correct order within 'ideal'."""
        seq_idx = 0
        for phase in ideal:
            if seq_idx < len(sequence) and sequence[seq_idx] == phase:
                seq_idx += 1
        return seq_idx >= 2  # At least 2 phases in correct order


def correlate(alerts: List[Alert], normalized_events: List[NormalizedEvent]) -> List[IncidentGroup]:
    """
    Correlate a list of alerts into IncidentGroups.

    Algorithm:
    1. Sort alerts by chronological event timestamp
    2. For each alert, find an open group where:
       - username OR source_ip matches
       - last_seen is within CORRELATION_WINDOW
    3. Add to existing group or create new one
    """
    if not alerts:
        return []

    # Build event_id -> NormalizedEvent mapping
    event_map: Dict[uuid.UUID, NormalizedEvent] = {e.id: e for e in normalized_events}

    def get_alert_timestamp(alert: Alert) -> datetime:
        # For each Alert, derive its chronological timestamp from its contributing_event_ids
        timestamps = [
            event_map[eid].timestamp for eid in alert.contributing_event_ids if eid in event_map
        ]
        if timestamps:
            return min(timestamps)
        return alert.detected_at  # Fallback

    # Annotate alerts with chronological timestamp for internal sorting
    for alert in alerts:
        alert._event_ts = get_alert_timestamp(alert)

    # Sort alerts by the chronological event timestamp
    sorted_alerts = sorted(alerts, key=lambda a: getattr(a, "_event_ts", a.detected_at))
    window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    groups: List[IncidentGroup] = []

    for alert in sorted_alerts:
        alert_ts = getattr(alert, "_event_ts", alert.detected_at)
        alert_ip = alert.metadata.get("source_ip")
        alert_user = alert.metadata.get("username")

        matched_group: Optional[IncidentGroup] = None

        for group in groups:
            if group.last_seen is None:
                continue
            # Time window check using event timestamp
            if (alert_ts - group.last_seen) > window:
                continue
            # Entity overlap check
            # Different explicit usernames should NOT be merged merely due to a shared IP
            if alert_user and group.username and alert_user != group.username:
                continue

            ip_match = alert_ip and group.source_ip and alert_ip == group.source_ip
            user_match = alert_user and group.username and alert_user == group.username
            if ip_match or user_match:
                matched_group = group
                break

        if matched_group is None:
            # Create new group
            new_group = IncidentGroup(
                source_ip=alert_ip,
                username=alert_user,
            )
            new_group.add_alert(alert, alert_ts)
            groups.append(new_group)
        else:
            # Update group entities (fill in any None values)
            if not matched_group.source_ip and alert_ip:
                matched_group.source_ip = alert_ip
            if not matched_group.username and alert_user:
                matched_group.username = alert_user
            matched_group.add_alert(alert, alert_ts)

    return groups
