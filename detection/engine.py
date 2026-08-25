from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from detection import Alert, NormalizedEvent
from detection.rules.account_compromise import AccountCompromiseRule
from detection.rules.brute_force import BruteForceRule
from detection.rules.privilege_escalation import PrivilegeEscalationRule


class DetectionEngine:
    def __init__(self) -> None:
        self._rules = [
            BruteForceRule(),
            AccountCompromiseRule(),
            PrivilegeEscalationRule(),
        ]

    def run(self, events: List[NormalizedEvent]) -> List[Alert]:
        if not events:
            return []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        indexed = self._build_index(sorted_events)

        all_alerts: List[Alert] = []
        for rule in self._rules:
            rule_alerts = rule.evaluate(sorted_events, indexed)
            all_alerts.extend(rule_alerts)

        deduped = self._deduplicate(all_alerts)
        return sorted(deduped, key=lambda a: a.detected_at)

    def _build_index(
        self,
        events: List[NormalizedEvent],
    ) -> Dict[Tuple[str, Optional[str]], List[NormalizedEvent]]:
        index: Dict[Tuple[str, Optional[str]], List[NormalizedEvent]] = defaultdict(list)
        for event in events:
            key = (event.source_ip, event.username)
            index[key].append(event)
        return index

    def _deduplicate(self, alerts: List[Alert]) -> List[Alert]:
        groups: Dict[Tuple, List[Alert]] = defaultdict(list)
        for alert in alerts:
            key = (
                alert.rule_name,
                alert.metadata.get("source_ip", ""),
                alert.metadata.get("username", ""),
            )
            groups[key].append(alert)

        result: List[Alert] = []
        for group_alerts in groups.values():
            if len(group_alerts) == 1:
                result.append(group_alerts[0])
                continue

            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            best = max(
                group_alerts,
                key=lambda a: (severity_order.get(a.severity.value, 0), a.confidence),
            )
            all_ids = []
            seen_ids = set()
            for a in group_alerts:
                for eid in a.contributing_event_ids:
                    if eid not in seen_ids:
                        all_ids.append(eid)
                        seen_ids.add(eid)
            best.contributing_event_ids = all_ids
            result.append(best)

        return result
