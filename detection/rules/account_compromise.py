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
    SUCCESS_GRACE_MINUTES: int = 5

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

        by_pair: Dict[Tuple[str, Optional[str]], List[NormalizedEvent]] = defaultdict(list)
        for event in events:
            key = (event.source_ip, event.username)
            by_pair[key].append(event)

        failure_window = timedelta(minutes=self.FAILURE_WINDOW_MINUTES)
        success_grace = timedelta(minutes=self.SUCCESS_GRACE_MINUTES)

        for (source_ip, username), pair_events in by_pair.items():
            if not username:
                continue

            sorted_events = sorted(pair_events, key=lambda e: e.timestamp)

            failures = [e for e in sorted_events if e.event_type == EventType.AUTH_FAILURE]
            successes = [e for e in sorted_events if e.event_type == EventType.AUTH_SUCCESS]

            if len(failures) < self.FAILURE_THRESHOLD or not successes:
                continue

            for i, anchor in enumerate(failures):
                window_end = anchor.timestamp + failure_window

                window_failures = [
                    f for f in failures[i:]
                    if f.timestamp <= window_end
                ]

                if len(window_failures) < self.FAILURE_THRESHOLD:
                    continue

                search_end = window_end + success_grace
                relevant_successes = [
                    s for s in successes
                    if anchor.timestamp <= s.timestamp <= search_end
                ]

                if not relevant_successes:
                    continue

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
                break

        return alerts

    def _calculate_confidence(
        self,
        failures: List[NormalizedEvent],
        success: NormalizedEvent,
        source_ip: str,
    ) -> float:
        count = len(failures)
        confidence = 0.70

        if count >= 10:
            confidence += 0.15
        elif count >= 5:
            confidence += 0.08
        elif count == 3:
            confidence -= 0.05

        all_same_ip = all(e.source_ip == source_ip for e in failures) and success.source_ip == source_ip
        if all_same_ip:
            confidence += 0.10

        return min(confidence, 0.95)
