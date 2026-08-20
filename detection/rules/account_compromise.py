"""
Rule 2: Account Compromise Detection

Two-phase detection:
  1. ≥ 3 AUTH_FAILURE events for (source_ip, username) within 30-minute window
  2. AUTH_SUCCESS for the same (source_ip, username) within or up to 5 minutes after

Confidence:
  - Base 0.70
  - More failures before success → higher confidence
  - Same IP for all failures + success: +0.10
  - Fewer failures (3–4): slightly lower (suspicious but weaker signal)
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from detection import Alert, AttackPhase, EventType, NormalizedEvent, Severity
from detection.rules import BaseRule


class AccountCompromiseRule(BaseRule):
    FAILURE_THRESHOLD: int = 3
    FAILURE_WINDOW_MINUTES: int = 30
    SUCCESS_GRACE_MINUTES: int = 5  # How long after the window a success can still trigger

    @property
    def rule_name(self) -> str:
        return "ACCOUNT_COMPROMISE"

    def evaluate(
        self,
        events: List[NormalizedEvent],
        indexed: Dict[Tuple, List[NormalizedEvent]],
    ) -> List[Alert]:
        alerts: List[Alert] = []
        seen_pairs: set = set()

        # Group all events by (source_ip, username)
        by_pair: Dict[Tuple[str, Optional[str]], List[NormalizedEvent]] = defaultdict(list)
        for event in events:
            key = (event.source_ip, event.username)
            by_pair[key].append(event)

        failure_window = timedelta(minutes=self.FAILURE_WINDOW_MINUTES)
        success_grace = timedelta(minutes=self.SUCCESS_GRACE_MINUTES)

        for (source_ip, username), pair_events in by_pair.items():
            if not username:
                continue  # Username is required for compromise detection

            sorted_events = sorted(pair_events, key=lambda e: e.timestamp)

            failures = [e for e in sorted_events if e.event_type == EventType.AUTH_FAILURE]
            successes = [e for e in sorted_events if e.event_type == EventType.AUTH_SUCCESS]

            if len(failures) < self.FAILURE_THRESHOLD or not successes:
                continue

            # Find windows of ≥3 failures, then check if a success followed
            for i, anchor in enumerate(failures):
                window_end = anchor.timestamp + failure_window

                # Failures in this window
                window_failures = [
                    f for f in failures[i:]
                    if f.timestamp <= window_end
                ]

                if len(window_failures) < self.FAILURE_THRESHOLD:
                    continue

                # Look for AUTH_SUCCESS within the window or grace period
                search_end = window_end + success_grace
                relevant_successes = [
                    s for s in successes
                    if anchor.timestamp <= s.timestamp <= search_end
                ]

                if not relevant_successes:
                    continue

                # Pick the first success as the compromise event
                compromise_event = relevant_successes[0]

                dedup_key = (source_ip, username, anchor.timestamp.replace(second=0, microsecond=0))
                if dedup_key in seen_pairs:
                    continue
                seen_pairs.add(dedup_key)

                failure_count = len(window_failures)
                confidence = self._calculate_confidence(
                    window_failures, compromise_event, source_ip
                )

                description = (
                    f"Account compromise: {failure_count} failed login attempts "
                    f"from {source_ip} targeting '{username}' followed by "
                    f"successful authentication at {compromise_event.timestamp.strftime('%H:%M:%S UTC')}"
                )

                all_event_ids = [e.id for e in window_failures] + [compromise_event.id]

                alerts.append(Alert(
                    id=uuid.uuid4(),
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    confidence=confidence,
                    description=description,
                    contributing_event_ids=all_event_ids,
                    metadata={
                        "source_ip": source_ip,
                        "username": username,
                        "failure_count": failure_count,
                        "compromise_event_id": str(compromise_event.id),
                        "compromise_timestamp": compromise_event.timestamp.isoformat(),
                        "window_start": anchor.timestamp.isoformat(),
                        "window_end": window_end.isoformat(),
                    },
                    attack_phase=AttackPhase.COMPROMISE,
                ))
                break  # One alert per (source_ip, username) pair

        return alerts

    def _calculate_confidence(
        self,
        failures: List[NormalizedEvent],
        success: NormalizedEvent,
        source_ip: str,
    ) -> float:
        count = len(failures)
        confidence = 0.70

        # More failures = higher confidence (attacker tried hard before succeeding)
        if count >= 10:
            confidence += 0.15
        elif count >= 5:
            confidence += 0.08
        elif count == 3:
            confidence -= 0.05  # Could be legitimate user with typos

        # Same IP throughout
        all_same_ip = all(e.source_ip == source_ip for e in failures) and success.source_ip == source_ip
        if all_same_ip:
            confidence += 0.10

        return min(confidence, 0.95)
