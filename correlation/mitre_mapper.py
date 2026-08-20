"""
MITRE ATT&CK Mapper

Maps attack hypothesis phases to MITRE ATT&CK technique identifiers.
Rule-based mapping — no LLM required.
"""

from __future__ import annotations

from typing import Any, Dict, List

from correlation.hypothesis import (
    ATTACK_TYPE_ACCOUNT_COMPROMISE,
    ATTACK_TYPE_ACCOUNT_COMPROMISE_WITH_ESCALATION,
    ATTACK_TYPE_BRUTE_FORCE,
    ATTACK_TYPE_PRIVILEGE_ESCALATION_ONLY,
)

MITRE_BASE_URL = "https://attack.mitre.org/techniques/"

# Technique registry for the 3 MVP scenarios
TECHNIQUE_REGISTRY: Dict[str, Dict[str, Any]] = {
    "T1110": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
        "url": f"{MITRE_BASE_URL}T1110/",
    },
    "T1110.001": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_technique_id": "T1110.001",
        "sub_technique_name": "Password Guessing",
        "url": f"{MITRE_BASE_URL}T1110/001/",
    },
    "T1110.003": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_technique_id": "T1110.003",
        "sub_technique_name": "Password Spraying",
        "url": f"{MITRE_BASE_URL}T1110/003/",
    },
    "T1078": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "sub_technique_id": None,
        "sub_technique_name": None,
        "url": f"{MITRE_BASE_URL}T1078/",
    },
    "T1078.003": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "sub_technique_id": "T1078.003",
        "sub_technique_name": "Local Accounts",
        "url": f"{MITRE_BASE_URL}T1078/003/",
    },
}

# Attack type → list of technique IDs to assign
ATTACK_TYPE_TO_TECHNIQUES: Dict[str, List[str]] = {
    ATTACK_TYPE_BRUTE_FORCE: ["T1110", "T1110.001"],
    ATTACK_TYPE_ACCOUNT_COMPROMISE: ["T1110", "T1110.001", "T1078"],
    ATTACK_TYPE_ACCOUNT_COMPROMISE_WITH_ESCALATION: ["T1110", "T1110.001", "T1078", "T1078.003"],
    ATTACK_TYPE_PRIVILEGE_ESCALATION_ONLY: ["T1078", "T1078.003"],
}

# Confidence per technique — brute force is high confidence, escalation slightly lower
TECHNIQUE_CONFIDENCE: Dict[str, float] = {
    "T1110": 0.95,
    "T1110.001": 0.90,
    "T1110.003": 0.75,
    "T1078": 0.85,
    "T1078.003": 0.80,
}


def map_techniques(attack_classification: str) -> List[Dict[str, Any]]:
    """
    Map an attack classification to a list of MITRE ATT&CK technique dicts.

    Returns a list ready for insertion into the attack_techniques table.
    """
    technique_ids = ATTACK_TYPE_TO_TECHNIQUES.get(attack_classification, ["T1110"])
    result = []
    for tid in technique_ids:
        if tid not in TECHNIQUE_REGISTRY:
            continue
        tech = TECHNIQUE_REGISTRY[tid].copy()
        tech["confidence"] = TECHNIQUE_CONFIDENCE.get(tid, 0.75)
        tech["mapping_source"] = "RULE_BASED"
        result.append(tech)
    return result
