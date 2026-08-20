"""
Attack Hypothesis Builder

Generates deterministic, template-based attack hypothesis JSON from an IncidentGroup + timeline.
No LLM required — all narratives are evidence-backed by the actual event sequence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from correlation.correlator import IncidentGroup
from correlation.timeline_builder import TimelineEntry
from detection import AttackPhase, EventType

# Classification constants
ATTACK_TYPE_BRUTE_FORCE = "BRUTE_FORCE"
ATTACK_TYPE_ACCOUNT_COMPROMISE = "ACCOUNT_COMPROMISE"
ATTACK_TYPE_ACCOUNT_COMPROMISE_WITH_ESCALATION = "ACCOUNT_COMPROMISE_WITH_ESCALATION"
ATTACK_TYPE_PRIVILEGE_ESCALATION_ONLY = "PRIVILEGE_ESCALATION"


NARRATIVE_TEMPLATES = {
    ATTACK_TYPE_BRUTE_FORCE: (
        "An attacker from {source_ip} conducted {failure_count} failed authentication attempts "
        "against user '{username}' over {duration_minutes} minute(s). "
        "No successful authentication was observed."
    ),
    ATTACK_TYPE_ACCOUNT_COMPROMISE: (
        "An attacker from {source_ip} successfully compromised the '{username}' account "
        "after {failure_count} failed login attempt(s). "
        "The account was taken over at {compromise_time}."
    ),
    ATTACK_TYPE_ACCOUNT_COMPROMISE_WITH_ESCALATION: (
        "An attacker from {source_ip} conducted a credential attack against '{username}', "
        "achieving account compromise after {failure_count} failed attempt(s) at {compromise_time}. "
        "The attacker subsequently escalated privileges at {escalation_time}, "
        "gaining elevated access to the system."
    ),
    ATTACK_TYPE_PRIVILEGE_ESCALATION_ONLY: (
        "User '{username}' experienced unauthorized privilege escalation at {escalation_time} "
        "following a recent authentication event."
    ),
}


def build_hypothesis(
    group: IncidentGroup,
    timeline: List[TimelineEntry],
) -> Dict[str, Any]:
    """
    Build the attack_hypothesis JSONB structure for an incident.

    Returns a dict ready for JSON serialization.
    """
    phases_data = _extract_phases(timeline)
    classification = _classify_attack(phases_data)
    narrative = _generate_narrative(classification, group, timeline, phases_data)

    return {
        "classification": classification,
        "phases": phases_data,
        "narrative": narrative,
        "confidence": round(group.overall_confidence, 3),
    }


def _extract_phases(timeline: List[TimelineEntry]) -> List[Dict[str, Any]]:
    """Aggregate timeline entries into phase summaries."""
    phase_order = [
        AttackPhase.INITIAL_ACCESS,
        AttackPhase.COMPROMISE,
        AttackPhase.ESCALATION,
        AttackPhase.IMPACT,
    ]

    phase_map: Dict[AttackPhase, List[TimelineEntry]] = {}
    for entry in timeline:
        if entry.phase not in phase_map:
            phase_map[entry.phase] = []
        phase_map[entry.phase].append(entry)

    # MITRE technique per phase
    phase_technique_map = {
        AttackPhase.INITIAL_ACCESS: ("T1110", "Brute Force"),
        AttackPhase.COMPROMISE:     ("T1078", "Valid Accounts"),
        AttackPhase.ESCALATION:     ("T1078.003", "Local Accounts"),
        AttackPhase.IMPACT:         ("T1005", "Data from Local System"),
    }

    phases_data = []
    for phase in phase_order:
        if phase not in phase_map:
            continue
        entries = phase_map[phase]
        technique_id, technique_name = phase_technique_map.get(phase, ("", ""))

        phases_data.append({
            "phase": phase.value,
            "technique": technique_id,
            "technique_name": technique_name,
            "description": entries[0].description,
            "event_ids": [str(e.event_id) for e in entries],
            "timestamp_start": entries[0].timestamp.isoformat(),
            "timestamp_end": entries[-1].timestamp.isoformat(),
            "event_count": len(entries),
        })

    return phases_data


def _classify_attack(phases_data: List[Dict[str, Any]]) -> str:
    """Determine the attack classification from which phases exist."""
    phase_names = {p["phase"] for p in phases_data}

    has_initial_access = AttackPhase.INITIAL_ACCESS.value in phase_names
    has_compromise     = AttackPhase.COMPROMISE.value in phase_names
    has_escalation     = AttackPhase.ESCALATION.value in phase_names

    if has_initial_access and has_compromise and has_escalation:
        return ATTACK_TYPE_ACCOUNT_COMPROMISE_WITH_ESCALATION
    elif has_initial_access and has_compromise:
        return ATTACK_TYPE_ACCOUNT_COMPROMISE
    elif has_escalation and not has_initial_access:
        return ATTACK_TYPE_PRIVILEGE_ESCALATION_ONLY
    else:
        return ATTACK_TYPE_BRUTE_FORCE


def _generate_narrative(
    classification: str,
    group: IncidentGroup,
    timeline: List[TimelineEntry],
    phases_data: List[Dict[str, Any]],
) -> str:
    """Fill in a narrative template with real event data."""
    template = NARRATIVE_TEMPLATES.get(classification, "Security incident detected.")

    # Count failures
    failure_count = sum(
        1 for e in timeline if e.event_type == EventType.AUTH_FAILURE
    )

    # Get compromise time
    compromise_entries = [e for e in timeline if e.event_type == EventType.AUTH_SUCCESS]
    compromise_time = (
        compromise_entries[0].timestamp.strftime("%H:%M:%S UTC")
        if compromise_entries else "unknown"
    )

    # Get escalation time
    escalation_entries = [e for e in timeline if e.event_type == EventType.PRIV_CHANGE]
    escalation_time = (
        escalation_entries[0].timestamp.strftime("%H:%M:%S UTC")
        if escalation_entries else "unknown"
    )

    # Duration in minutes
    duration_minutes = 0
    if group.first_seen and group.last_seen:
        duration_minutes = max(
            1, int((group.last_seen - group.first_seen).total_seconds() / 60)
        )

    return template.format(
        source_ip=group.source_ip or "unknown",
        username=group.username or "unknown",
        failure_count=failure_count,
        duration_minutes=duration_minutes,
        compromise_time=compromise_time,
        escalation_time=escalation_time,
    )
