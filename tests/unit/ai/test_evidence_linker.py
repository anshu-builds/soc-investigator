import pytest
from ai.evidence_linker import (
    classify_answer_type,
    extract_and_validate_citations,
    extract_mitre_references,
    extract_rag_sources,
)


def test_classify_factual_with_citations():
    res = classify_answer_type("The user logged in at 10:00 [EV-001].")
    assert res == "FACTUAL"


def test_classify_inference_without_citations():
    res = classify_answer_type("This activity suggests a lateral movement attempt across the domain.")
    assert res == "INFERENCE"

    res = classify_answer_type("It appears to be a brute force attack based on observed volume.")
    assert res == "INFERENCE"


def test_classify_recommendation_without_citations():
    res = classify_answer_type("We recommend you isolate the host immediately.")
    assert res == "RECOMMENDATION"

    res = classify_answer_type("The next step should be password reset for affected accounts.")
    assert res == "RECOMMENDATION"


def test_classify_cannot_determine_variants():
    variants = [
        "I cannot determine this from the available evidence.",
        "There is insufficient evidence to conclude the attacker identity.",
        "Insufficient information is provided to verify this claim.",
        "There is not enough information to confirm the source workstation.",
        "We do not have enough information to answer this question.",
        "The available evidence does not establish lateral movement.",
        "We cannot establish from the provided evidence if data was exfiltrated.",
        "We cannot establish from the available evidence that a breach occurred.",
        "There is no evidence supports the claim of privilege escalation.",
        "There is no evidence to suggest administrative compromise.",
        "I am unable to determine the full extent of the attack.",
    ]
    for variant in variants:
        assert classify_answer_type(variant) == "CANNOT_DETERMINE", f"Failed for: {variant}"


def test_classify_uncertainty_with_citation_remains_factual():
    # If the response mentions uncertainty about X but provides cited evidence for Y, it should be FACTUAL
    res = classify_answer_type("I cannot determine whether X happened, but the evidence shows Y [EV-001].")
    assert res == "FACTUAL"


def test_classify_unrelated_negations():
    # Common words like 'not', 'unknown', 'unclear' in factual context must not trigger CANNOT_DETERMINE
    res = classify_answer_type("The user was not authorized to access the system [EV-002].")
    assert res == "FACTUAL"

    res = classify_answer_type("The status was unknown prior to the alert [EV-003].")
    assert res == "FACTUAL"


def test_extract_and_validate_citations():
    ev_map = {"EV-001": "uuid1", "EV-002": "uuid2"}
    llm_resp = "Valid [EV-001] and another [EV-002] but fake [EV-999]."
    valid, invalid, cleaned = extract_and_validate_citations(llm_resp, ev_map)
    assert set(valid) == {"uuid1", "uuid2"}
    assert invalid == ["EV-999"]
    assert "[EV-999⚠️UNVERIFIED]" in cleaned
    assert "[EV-001]" in cleaned


def test_extract_mitre_and_rag_sources():
    llm_resp = "Techniques observed: T1110 and T1078.001 were noted."
    mitre = extract_mitre_references(llm_resp)
    assert set(mitre) == {"T1110", "T1078.001"}

    rag_chunks = [
        {"title": "Brute Force Response Playbook", "source": "playbook.md"},
        {"source": "MITRE ATT&CK T1110"},
        {"text": "generic text chunk"},
    ]
    sources = extract_rag_sources(rag_chunks)
    assert "Brute Force Response Playbook" in sources
    assert "MITRE ATT&CK T1110" in sources
