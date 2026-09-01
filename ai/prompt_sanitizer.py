"""Prompt sanitization, XML boundary serialization, and indirect prompt injection defense."""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional


def escape_xml_text(val: Any) -> str:
    """Safely escapes text for inclusion within XML structural delimiters.

    Escapes &, <, >, ", and ' so that attacker-controlled log fields or user inputs
    cannot break out of XML tag boundaries (e.g., </untrusted_incident_evidence>).
    Also purges NULL bytes and unprintable control characters.
    """
    if val is None:
        return ""
    text = str(val)
    # Purge ASCII control characters except \t, \n, \r
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Escape &, <, >, ", '
    return html.escape(text, quote=True).replace("&#x27;", "&apos;")


def sanitize_rag_query(query: str, max_length: int = 500) -> str:
    """Sanitizes queries before submitting to vector or keyword RAG retrievers.

    Prevents massive injection payloads or control characters from disrupting
    retriever queries while preserving searchable terms.
    """
    if not query:
        return ""
    # Collapse multiple whitespaces and strip control characters
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(query))
    cleaned = " ".join(cleaned.split())
    return cleaned[:max_length].strip()


def serialize_untrusted_evidence(
    incident: Any,
    evidence_items: List[Any],
    evidence_map: Dict[str, str],
) -> str:
    """Serializes incident metadata and evidence records into structured XML.

    Encloses all untrusted security event fields inside <untrusted_incident_evidence>
    tags with full XML character escaping, preventing prompt injection payloads
    from breaking into system-level prompt instructions.
    """
    reverse_map = {v: k for k, v in evidence_map.items()}

    lines: List[str] = ["<untrusted_incident_evidence>"]

    # Incident Metadata
    lines.append("  <incident_metadata>")
    lines.append(f"    <incident_id>{escape_xml_text(getattr(incident, 'id', ''))}</incident_id>")
    lines.append(f"    <title>{escape_xml_text(getattr(incident, 'title', ''))}</title>")
    lines.append(f"    <severity>{escape_xml_text(getattr(incident, 'severity', ''))}</severity>")
    confidence_val = getattr(incident, "confidence", 0.0) or 0.0
    lines.append(f"    <confidence>{confidence_val:.0%}</confidence>")
    lines.append(f"    <status>{escape_xml_text(getattr(incident, 'status', ''))}</status>")
    if getattr(incident, "affected_username", None):
        lines.append(f"    <affected_username>{escape_xml_text(incident.affected_username)}</affected_username>")
    if getattr(incident, "source_ip", None):
        lines.append(f"    <attacking_source_ip>{escape_xml_text(incident.source_ip)}</attacking_source_ip>")
    first_seen = getattr(incident, "first_seen", None)
    last_seen = getattr(incident, "last_seen", None)
    if first_seen and last_seen:
        timeframe_str = (
            f"{first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} to "
            f"{last_seen.strftime('%H:%M:%S UTC')}"
        )
        lines.append(f"    <timeframe>{escape_xml_text(timeframe_str)}</timeframe>")
    lines.append(f"    <total_events>{getattr(incident, 'event_count', 0)}</total_events>")
    lines.append("  </incident_metadata>")

    # Attack Narrative & Phases
    hypothesis = getattr(incident, "attack_hypothesis", None)
    if hypothesis and isinstance(hypothesis, dict):
        narrative = hypothesis.get("narrative", "")
        if narrative:
            lines.append("  <attack_narrative>")
            lines.append(f"    {escape_xml_text(narrative)}")
            lines.append("  </attack_narrative>")

        phases = hypothesis.get("phases", [])
        if phases and isinstance(phases, list):
            lines.append("  <attack_phases>")
            for i, phase in enumerate(phases, 1):
                if isinstance(phase, dict):
                    ts_start = str(phase.get("timestamp_start", ""))[:19].replace("T", " ")
                    lines.append(
                        f'    <phase index="{i}" name="{escape_xml_text(phase.get("phase", ""))}" '
                        f'technique="{escape_xml_text(phase.get("technique", ""))}" '
                        f'timestamp="{escape_xml_text(ts_start)}">'
                    )
                    lines.append(f"      {escape_xml_text(phase.get('description', ''))}")
                    lines.append("    </phase>")
            lines.append("  </attack_phases>")

    # MITRE ATT&CK Techniques
    techniques = getattr(incident, "techniques", [])
    if techniques:
        lines.append("  <mitre_techniques>")
        for tech in techniques:
            tech_id = getattr(tech, "technique_id", "")
            sub = f" > {tech.sub_technique_name}" if getattr(tech, "sub_technique_name", None) else ""
            tactic = getattr(tech, "tactic", "")
            tech_name = getattr(tech, "technique_name", "")
            lines.append(
                f'    <technique id="{escape_xml_text(tech_id)}" tactic="{escape_xml_text(tactic)}">'
                f"{escape_xml_text(tech_name)}{escape_xml_text(sub)}</technique>"
            )
        lines.append("  </mitre_techniques>")

    # Evidence Records
    lines.append("  <evidence_list>")
    for ev in evidence_items:
        short_id = reverse_map.get(str(getattr(ev, "id", "")), "EV-???")
        event = getattr(ev, "event", None)
        if event is None:
            continue
        ts = event.timestamp.strftime("%H:%M:%S UTC") if getattr(event, "timestamp", None) else "N/A"
        event_type = getattr(event, "event_type", "UNKNOWN")
        source_ip = getattr(event, "source_ip", "")
        dest_ip = getattr(event, "destination_ip", "")
        username = getattr(event, "username", "")
        hostname = getattr(event, "hostname", "")
        role = getattr(ev, "role", "")
        desc = getattr(event, "description", "")

        lines.append(f'    <event evidence_id="[{short_id}]">')
        lines.append(f"      <timestamp>{escape_xml_text(ts)}</timestamp>")
        lines.append(f"      <event_type>{escape_xml_text(event_type)}</event_type>")
        lines.append(f"      <source_ip>{escape_xml_text(source_ip)}</source_ip>")
        if dest_ip:
            lines.append(f"      <destination_ip>{escape_xml_text(dest_ip)}</destination_ip>")
        if username:
            lines.append(f"      <username>{escape_xml_text(username)}</username>")
        if hostname:
            lines.append(f"      <hostname>{escape_xml_text(hostname)}</hostname>")
        if role:
            lines.append(f"      <role>{escape_xml_text(role)}</role>")
        if desc:
            lines.append(f"      <description>{escape_xml_text(desc)}</description>")
        lines.append("    </event>")
    lines.append("  </evidence_list>")

    lines.append("</untrusted_incident_evidence>")
    return "\n".join(lines)


def serialize_conversation_history(chat_history: Optional[List[Any]]) -> str:
    """Serializes previous conversation history turns into structured XML.

    Encloses dialogue turns in <conversation_history> tags with escaped content
    so previous user or assistant messages cannot inject instructions into system prompts.
    """
    if not chat_history:
        return ""

    lines: List[str] = ["<conversation_history>"]
    has_valid_messages = False

    for msg in chat_history:
        if isinstance(msg, dict):
            role_raw = str(msg.get("role", "unknown")).lower()
            content = str(msg.get("content") or "").strip()
        else:
            role_raw = str(getattr(msg, "role", "unknown")).lower()
            content = str(getattr(msg, "content", "") or "").strip()

        if not content:
            continue

        role_tag = "analyst" if role_raw in ("user", "human", "analyst") else "assistant"
        lines.append(f'  <message role="{role_tag}">{escape_xml_text(content)}</message>')
        has_valid_messages = True

    lines.append("</conversation_history>")
    return "\n".join(lines) if has_valid_messages else ""


def serialize_procedural_guidance(rag_chunks: List[Dict[str, Any]]) -> str:
    """Serializes RAG retrieval chunks into structured <procedural_guidance> XML tags."""
    if not rag_chunks:
        return ""

    lines: List[str] = ["<procedural_guidance>"]
    for chunk in rag_chunks:
        if not isinstance(chunk, dict):
            continue
        title = chunk.get("title") or chunk.get("source") or "Reference Playbook"
        text = chunk.get("text", "")
        lines.append(f'  <playbook title="{escape_xml_text(title)}">')
        lines.append(f"    {escape_xml_text(text)}")
        lines.append("  </playbook>")
    lines.append("</procedural_guidance>")
    return "\n".join(lines)
