"""
Rule 1: Brute Force Detection

Logic:
  - Sliding 5-minute window
  - Threshold: ≥ 5 AUTH_FAILURE events
  - Grouping key: (source_ip, username)

Confidence:
  - Base 0.6 + 0.04 per failure beyond threshold (capped 0.95)
  - Same IP throughout: +0.10
  - All failures within 60s: +0.05

Severity:
  - 5-9 failures  → MEDIUM
  - 10-19 failures → HIGH
  - ≥20 or automated (< 1s avg interval) → CRITICAL
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from detection import Alert, AttackPhase, EventType, NormalizedEvent, Severity
from detection.rules import BaseRule


class BruteForceRule(BaseRule):
    WINDOW_MINUTES: int = 5
    THRESHOLD: int = 5

    @property
    def rule_name(self) -> str:
        return "BRUTE_FORCE"

    def evaluate(
        self,
        events: List[NormalizedEvent],
        indexed: Dict[Tuple, List[NormalizedEvent]],
    ) -> List[Alert]:
        alerts: List[Alert] = []
        seen_windows: set = set()  # Deduplication: (source_ip, username, window_start_minute)

        # Group AUTH_FAILURE events by (source_ip, username)
        failure_groups: Dict[Tuple[str, Optional[str]], List[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == EventType.AUTH_FAILURE:
                key = (event.source_ip, event.username)
                failure_groups[key].append(event)

        window = timedelta(minutes=self.WINDOW_MINUTES)

        for (source_ip, username), failures in failure_groups.items():
            if len(failures) < self.THRESHOLD:
                continue

            # Slide window over sorted failures
            failures_sorted = sorted(failures, key=lambda e: e.timestamp)

            i = 0
            while i < len(failures_sorted):
                anchor = failures_sorted[i]
                window_end = anchor.timestamp + window

                # Collect all failures within this window
                window_events = [
                    e for e in failures_sorted[i:]
                    if e.timestamp <= window_end
                ]

                if len(window_events) < self.THRESHOLD:
                    i += 1
                    continue

                # Dedup: use (source_ip, username, window_minute) as key
                dedup_key = (
                    source_ip,
                    username or "",
                    anchor.timestamp.replace(second=0, microsecond=0),
                )
                if dedup_key in seen_windows:
                    i += 1
                    continue
                seen_windows.add(dedup_key)

                count = len(window_events)
                severity = self._calculate_severity(window_events)
                confidence = self._calculate_confidence(window_events, source_ip)

                duration_secs = (
                    window_events[-1].timestamp - window_events[0].timestamp
                ).total_seconds()

                description = (
                    f"Brute force detected: {count} failed login attempts "
                    f"from {source_ip} targeting user '{username or 'unknown'}' "
                    f"over {int(duration_secs)}s"
                )

                alerts.append(Alert(
                    id=uuid.uuid4(),
                    rule_name=self.rule_name,
                    severity=severity,
                    confidence=confidence,
                    description=description,
                    contributing_event_ids=[e.id for e in window_events],
                    metadata={
                        "source_ip": source_ip,
                        "username": username,
                        "failed_count": count,
                        "time_window_seconds": int(duration_secs),
                        "window_start": window_events[0].timestamp.isoformat(),
                        "window_end": window_events[-1].timestamp.isoformat(),
                    },
                    attack_phase=AttackPhase.INITIAL_ACCESS,
                ))

                # Advance past this window to avoid overlapping sub-windows
                i += max(1, len(window_events))

        return alerts

    def _calculate_severity(self, window_events: List[NormalizedEvent]) -> Severity:
        count = len(window_events)
        if count >= 20:
            return Severity.CRITICAL

        # Check if automated: average < 1s between attempts
        if len(window_events) >= 5:
            intervals = [
                (window_events[j].timestamp - window_events[j-1].timestamp).total_seconds()
                for j in range(1, len(window_events))
            ]
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval < 1.0:
                return Severity.CRITICAL

        if count >= 10:
            return Severity.HIGH
        return Severity.MEDIUM

    def _calculate_confidence(
        self,
        window_events: List[NormalizedEvent],
        source_ip: str,
    ) -> float:
        count = len(window_events)
        confidence = 0.60
        # +0.04 per failure beyond threshold, capped at 0.95
        extra = min((count - self.THRESHOLD) * 0.04, 0.35)
        confidence += extra

        # All from same IP
        all_same_ip = all(e.source_ip == source_ip for e in window_events)
        if all_same_ip:
            confidence += 0.10

        # Fast attack (all within 60s)
        duration = (window_events[-1].timestamp - window_events[0].timestamp).total_seconds()
        if duration <= 60:
            confidence += 0.05

        return min(confidence, 0.95)
