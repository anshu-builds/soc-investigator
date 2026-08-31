from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set


IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Matches 'user "sarah.miller"', "user sarah.miller", "username admin", "account admin"
USERNAME_PATTERN = re.compile(
    r"(?:user|username|account)\s+['\"]?([a-zA-Z0-9_.\-]{2,40})['\"]?",
    re.IGNORECASE,
)

# Matches "for <username>" e.g. "for admin", "for sarah.miller"
FOR_USER_PATTERN = re.compile(
    r"\bfor\s+['\"]?([a-zA-Z0-9_.\-]{2,40})['\"]?",
    re.IGNORECASE,
)

QUOTED_TOKEN_PATTERN = re.compile(r"['\"]([a-zA-Z0-9_.\-]{2,40})['\"]")

# MITRE ATT&CK technique pattern: T1110, T1078, T1059.001
MITRE_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

# FQDN hostnames: *.corp.local, *.internal, *.prod, *.dev
HOSTNAME_PATTERN = re.compile(
    r"\b([a-zA-Z0-9\-]+\.(?:corp|local|internal|prod|dev)\.?[a-zA-Z0-9\-.]*)\b",
    re.IGNORECASE,
)

# Keyword-triggered bare hostnames: "host web-server-01", "on web-server-01",
# "server dc-01", "hostname firewall-02"
BARE_HOSTNAME_PATTERN = re.compile(
    r"(?:host|hostname|server|on)\s+['\"]?([a-zA-Z][a-zA-Z0-9]*(?:-[a-zA-Z0-9]+)+(?:-\d+)?)['\"]?",
    re.IGNORECASE,
)

# Stopwords excluded from being interpreted as usernames when captured via "for ..."
_USERNAME_STOPWORDS: Set[str] = {
    "events", "incidents", "logs", "failures", "attacks", "today", "yesterday",
    "hours", "days", "weeks", "last", "past", "critical", "high", "medium",
    "low", "all", "each", "any", "this", "that", "the", "me", "us", "more",
    "details", "help", "activity", "evidence", "stuff", "wazuh", "server",
    "host", "hostname", "auth", "authentication", "login", "logins",
    "brute", "compromise", "escalation", "technique", "techniques", "mitre",
}

EVENT_TYPE_KEYWORDS = {
    "AUTH_FAILURE": [
        "failed login", "failed logins", "failed attempt", "failed authentication",
        "brute force", "brute-force", "password guessing", "login failure",
        "authentication failure", "authentication failures",
    ],
    "AUTH_SUCCESS": [
        "successful login", "successful logins", "logged in", "authenticated",
        "successful authentication",
    ],
    "PRIV_CHANGE": [
        "privilege escalation", "privileges", "escalated", "elevated",
        "admin rights", "sudo", "root access",
    ],
    "FILE_ACCESS": [
        "file access", "accessed file", "read file", "sensitive file",
        "downloaded", "exfiltrat",
    ],
    "PROCESS_EXEC": [
        "process", "executed", "ran a command", "command execution",
    ],
}

SEVERITY_KEYWORDS = {
    "CRITICAL": ["critical"],
    "HIGH": ["high severity", "high-severity", " high "],
    "MEDIUM": ["medium severity", "medium-severity"],
    "LOW": ["low severity", "low-severity"],
}

ATTACK_TYPE_KEYWORDS = {
    "BRUTE_FORCE": ["brute force", "brute-force", "password spray", "password guessing"],
    "ACCOUNT_COMPROMISE": ["account compromise", "compromised account", "account takeover"],
    "ACCOUNT_COMPROMISE_WITH_ESCALATION": ["compromise and escalation", "compromise + escalation"],
    "PRIVILEGE_ESCALATION": ["privilege escalation", "priv esc", "privesc"],
}

# "last 24 hours", "past 2 days", "since yesterday", "last week"
RELATIVE_TIME_PATTERN = re.compile(
    r"(?:last|past)\s+(\d+)\s*(hour|hours|day|days|week|weeks|minute|minutes)",
    re.IGNORECASE,
)
TODAY_PATTERN = re.compile(r"\btoday\b", re.IGNORECASE)
YESTERDAY_PATTERN = re.compile(r"\byesterday\b", re.IGNORECASE)


@dataclass
class ExtractedEntities:
    ips: List[str] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    event_types: List[str] = field(default_factory=list)
    attack_types: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    raw_text: str = ""

    def is_empty(self) -> bool:
        return not any([
            self.ips, self.usernames, self.hostnames,
            self.event_types, self.attack_types, self.severities,
            self.mitre_techniques, self.time_start, self.time_end,
        ])


def extract_entities(text: str, now: Optional[datetime] = None) -> ExtractedEntities:
    """Deterministic, rule-based entity extraction from an analyst's natural-
    language question. No LLM call — this must be fast, auditable, and
    reproducible, since it feeds a security query.
    """
    now = now or datetime.now(timezone.utc)
    lower = text.lower()

    ips = list(dict.fromkeys(IP_PATTERN.findall(text)))

    usernames: List[str] = []
    for m in USERNAME_PATTERN.findall(text):
        m_clean = m.strip().rstrip(".,?!;: '\"")
        if m_clean and not IP_PATTERN.match(m_clean) and m_clean.lower() not in _USERNAME_STOPWORDS:
            usernames.append(m_clean)

    for m in FOR_USER_PATTERN.findall(text):
        m_clean = m.strip().rstrip(".,?!;: '\"")
        if (
            m_clean
            and not IP_PATTERN.match(m_clean)
            and m_clean.lower() not in _USERNAME_STOPWORDS
            and m_clean not in usernames
        ):
            usernames.append(m_clean)

    if not usernames:
        # Fall back to quoted tokens that aren't IPs or hostnames or stopwords
        for tok in QUOTED_TOKEN_PATTERN.findall(text):
            tok_clean = tok.strip().rstrip(".,?!;: '\"")
            if (
                tok_clean
                and not IP_PATTERN.match(tok_clean)
                and "." not in tok_clean
                and tok_clean.lower() not in _USERNAME_STOPWORDS
            ):
                usernames.append(tok_clean)

    usernames = list(dict.fromkeys(usernames))

    # FQDN hostnames first
    hostnames = list(dict.fromkeys(h.rstrip(".,?!;: '\"") for h in HOSTNAME_PATTERN.findall(text)))
    # Bare hostnames via keyword trigger (e.g. "on web-server-01")
    for m in BARE_HOSTNAME_PATTERN.findall(text):
        m_clean = m.strip().rstrip(".,?!;: '\"")
        if (
            m_clean
            and m_clean not in hostnames
            and not IP_PATTERN.match(m_clean)
            and m_clean.lower() not in _USERNAME_STOPWORDS
        ):
            hostnames.append(m_clean)

    mitre_techniques = list(dict.fromkeys(m.upper() for m in MITRE_PATTERN.findall(text)))

    event_types = [
        etype for etype, kws in EVENT_TYPE_KEYWORDS.items()
        if any(kw in lower for kw in kws)
    ]

    attack_types = [
        atype for atype, kws in ATTACK_TYPE_KEYWORDS.items()
        if any(kw in lower for kw in kws)
    ]

    severities = [
        sev for sev, kws in SEVERITY_KEYWORDS.items()
        if any(kw in lower for kw in kws)
    ]

    time_start, time_end = _extract_time_range(lower, now)

    return ExtractedEntities(
        ips=ips,
        usernames=usernames,
        hostnames=hostnames,
        event_types=event_types,
        attack_types=attack_types,
        severities=severities,
        mitre_techniques=mitre_techniques,
        time_start=time_start,
        time_end=time_end,
        raw_text=text,
    )


def _extract_time_range(lower: str, now: datetime) -> tuple[Optional[datetime], Optional[datetime]]:
    match = RELATIVE_TIME_PATTERN.search(lower)
    if match:
        qty = int(match.group(1))
        unit = match.group(2)
        if unit.startswith("minute"):
            delta = timedelta(minutes=qty)
        elif unit.startswith("hour"):
            delta = timedelta(hours=qty)
        elif unit.startswith("day"):
            delta = timedelta(days=qty)
        else:  # week
            delta = timedelta(weeks=qty)
        return now - delta, now

    if TODAY_PATTERN.search(lower):
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, now

    if YESTERDAY_PATTERN.search(lower):
        start = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        return start, end

    return None, None
