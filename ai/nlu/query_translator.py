from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

from sqlalchemy import func, select
from sqlalchemy.sql import Select

from ai.nlu.entities import ExtractedEntities, extract_entities
from ai.nlu.intent import Intent, classify_intent
from backend.models import AttackTechnique, Incident, SecurityEvent


@dataclass
class QuerySpec:
    """A fully-resolved, structured representation of an analyst's natural-
    language question. This is the artifact that should be logged/audited —
    it's the deterministic 'query' half of the original PS ask (NL -> SIEM
    query), decoupled from whichever backing store executes it.
    """
    intent: Intent
    entities: ExtractedEntities
    target: str  # "security_events" | "incidents"
    limit: int = 100


@dataclass
class TranslationResult:
    query_spec: Optional[QuerySpec]
    needs_clarification: bool = False
    clarification_question: Optional[str] = None
    clarification_options: List[str] = field(default_factory=list)


_TARGET_BY_INTENT = {
    Intent.SEARCH_EVENTS: "security_events",
    Intent.COUNT: "security_events",
    Intent.INCIDENT_SUMMARY: "incidents",
    Intent.TIMELINE: "incidents",
    Intent.MITRE_LOOKUP: "incidents",
    Intent.RECOMMEND_ACTIONS: "incidents",
}


def _resolve_target(intent: Intent, entities: ExtractedEntities) -> str:
    """Determine the query target table, using entity context to override
    defaults when appropriate. For example, COUNT with severity but no
    event_type should target incidents, not security_events.
    """
    default = _TARGET_BY_INTENT.get(intent, "security_events")

    # If the intent is COUNT or SEARCH_EVENTS but entities only contain
    # incident-level filters (severity, attack_type, mitre_techniques) and no
    # event-level filters (event_type, IP, username, hostname), route to incidents.
    if intent in (Intent.COUNT, Intent.SEARCH_EVENTS):
        has_incident_filters = bool(entities.severities or entities.attack_types or entities.mitre_techniques)
        has_event_filters = bool(entities.event_types or entities.ips
                                 or entities.usernames or entities.hostnames)
        if has_incident_filters and not has_event_filters:
            return "incidents"

    return default


def translate(text: str) -> TranslationResult:
    """Translate a raw analyst question into a QuerySpec, or flag ambiguity.

    Ambiguity handling is a first-class outcome, not a fallback: if the
    question can't be resolved to a concrete, safe query, we say so rather
    than guessing and returning misleading results.
    """
    text = text.strip()
    if not text:
        return TranslationResult(
            query_spec=None,
            needs_clarification=True,
            clarification_question="What would you like me to investigate?",
        )

    intent = classify_intent(text)
    entities = extract_entities(text)

    if intent == Intent.UNKNOWN:
        return TranslationResult(
            query_spec=None,
            needs_clarification=True,
            clarification_question=(
                "I'm not sure what you're asking. Are you looking to search "
                "events, get an incident summary, see a timeline, or get "
                "recommended actions?"
            ),
            clarification_options=[
                "Search events", "Incident summary", "Timeline", "Recommended actions",
            ],
        )

    # SEARCH_EVENTS / COUNT with zero entities is too broad to run safely —
    # it would return/scan the entire events table.
    if intent in (Intent.SEARCH_EVENTS, Intent.COUNT) and entities.is_empty():
        return TranslationResult(
            query_spec=None,
            needs_clarification=True,
            clarification_question=(
                "Which user, IP, host, or time range should I search? "
                "(e.g. \"failed logins from 10.10.5.200 in the last 24 hours\")"
            ),
        )

    target = _resolve_target(intent, entities)
    spec = QuerySpec(intent=intent, entities=entities, target=target)
    return TranslationResult(query_spec=spec, needs_clarification=False)


def build_query(spec: QuerySpec) -> Select:
    """Turn a QuerySpec into an executable SQLAlchemy Select statement."""
    if spec.target == "security_events":
        return _build_events_query(spec)
    return _build_incidents_query(spec)


def _build_events_query(spec: QuerySpec) -> Select:
    e = spec.entities
    q = select(SecurityEvent)

    if e.ips:
        q = q.where(SecurityEvent.source_ip.in_(e.ips))
    if e.usernames:
        q = q.where(SecurityEvent.username.in_(e.usernames))
    if e.hostnames:
        q = q.where(SecurityEvent.hostname.in_(e.hostnames))
    if e.event_types:
        q = q.where(SecurityEvent.event_type.in_(e.event_types))
    if e.time_start:
        q = q.where(SecurityEvent.timestamp >= e.time_start)
    if e.time_end:
        q = q.where(SecurityEvent.timestamp <= e.time_end)

    if spec.intent == Intent.COUNT:
        return select(func.count()).select_from(q.subquery())

    return q.order_by(SecurityEvent.timestamp.desc()).limit(spec.limit)


def _build_incidents_query(spec: QuerySpec) -> Select:
    e = spec.entities
    q = select(Incident)

    if e.mitre_techniques:
        q = q.join(Incident.techniques).where(AttackTechnique.technique_id.in_(e.mitre_techniques)).distinct()

    if e.ips:
        q = q.where(Incident.source_ip.in_(e.ips))
    if e.usernames:
        q = q.where(Incident.affected_username.in_(e.usernames))
    if e.hostnames:
        q = q.where(Incident.affected_host.in_(e.hostnames))
    if e.attack_types:
        q = q.where(Incident.attack_type.in_(e.attack_types))
    if e.severities:
        q = q.where(Incident.severity.in_(e.severities))
    if e.time_start:
        q = q.where(Incident.first_seen >= e.time_start)
    if e.time_end:
        q = q.where(Incident.first_seen <= e.time_end)

    if spec.intent == Intent.COUNT:
        return select(func.count()).select_from(q.subquery())

    return q.order_by(Incident.created_at.desc()).limit(spec.limit)
