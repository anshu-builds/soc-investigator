from __future__ import annotations

from typing import Any, Sequence

from ai.nlu.intent import Intent
from ai.nlu.query_translator import QuerySpec
from backend.models import Incident, SecurityEvent


def explain_results(spec: QuerySpec, results: Sequence[Any]) -> str:
    """Deterministic natural-language summary of query results. This is
    intentionally NOT an LLM call: the numbers and facts here must be exact,
    since they may drive downstream investigation decisions. Save the LLM for
    the interpretive layer (ai/investigation_chain.py), not for restating
    query output.
    """
    if spec.intent == Intent.COUNT:
        count = results[0] if results else 0
        label = "incident(s)" if spec.target == "incidents" else "event(s)"
        return f"Found {count} matching {label}."

    if spec.target == "security_events":
        return _explain_events(spec, results)  # type: ignore[arg-type]

    return _explain_incidents(spec, results)  # type: ignore[arg-type]


def _explain_events(spec: QuerySpec, events: Sequence[SecurityEvent]) -> str:
    if not events:
        return "No matching events found for that query."

    lines = [f"Found {len(events)} matching event(s):"]
    for ev in events[:20]:
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        user = ev.username or "unknown user"
        lines.append(f"- {ts} — {ev.event_type} — {user} @ {ev.source_ip}")
    if len(events) > 20:
        lines.append(f"...and {len(events) - 20} more.")
    return "\n".join(lines)


def _explain_incidents(spec: QuerySpec, incidents: Sequence[Incident]) -> str:
    if not incidents:
        return "No matching incidents found for that query."

    lines = [f"Found {len(incidents)} matching incident(s):"]
    for inc in incidents[:20]:
        lines.append(
            f"- [{inc.severity}] {inc.title} "
            f"(status: {inc.status}, confidence: {inc.confidence:.0%}) "
            f"— id {inc.id}"
        )
    if len(incidents) > 20:
        lines.append(f"...and {len(incidents) - 20} more.")
    return "\n".join(lines)
