from __future__ import annotations

from enum import Enum
from typing import Dict, List


class Intent(str, Enum):
    SEARCH_EVENTS = "SEARCH_EVENTS"          # "show me failed logins from 10.0.0.5"
    INCIDENT_SUMMARY = "INCIDENT_SUMMARY"    # "what happened in incident X" / "any active incidents"
    TIMELINE = "TIMELINE"                    # "walk me through the attack timeline"
    MITRE_LOOKUP = "MITRE_LOOKUP"            # "what MITRE techniques were used"
    RECOMMEND_ACTIONS = "RECOMMEND_ACTIONS"  # "what should I do about this"
    COUNT = "COUNT"                          # "how many failed logins were there"
    UNKNOWN = "UNKNOWN"


_INTENT_KEYWORDS: Dict[Intent, List[str]] = {
    Intent.COUNT: [
        "how many", "count of", "number of",
    ],
    Intent.TIMELINE: [
        "timeline", "walk me through", "sequence of events", "what happened first",
        "order of events", "chronolog",
    ],
    Intent.MITRE_LOOKUP: [
        "mitre", "att&ck", "attack technique", "technique id", "tactic",
    ],
    Intent.RECOMMEND_ACTIONS: [
        "what should i do", "recommend", "containment", "how do i respond",
        "next steps", "remediat", "how do i fix",
    ],
    Intent.INCIDENT_SUMMARY: [
        "incident", "summary", "summarize", "what happened", "explain the attack",
        "any active", "open incidents",
    ],
    Intent.SEARCH_EVENTS: [
        "show", "find", "search", "list", "events from", "logs from", "get all", "pull up",
    ],
}

# Order matters: more specific intents are checked before generic ones.
_PRIORITY_ORDER = [
    Intent.COUNT,
    Intent.TIMELINE,
    Intent.MITRE_LOOKUP,
    Intent.RECOMMEND_ACTIONS,
    Intent.INCIDENT_SUMMARY,
    Intent.SEARCH_EVENTS,
]


def classify_intent(text: str) -> Intent:
    lower = text.lower()
    for intent in _PRIORITY_ORDER:
        keywords = _INTENT_KEYWORDS[intent]
        if any(kw in lower for kw in keywords):
            return intent
    return Intent.UNKNOWN
