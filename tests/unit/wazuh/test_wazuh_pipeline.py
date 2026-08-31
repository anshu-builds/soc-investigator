"""Integration tests for Wazuh alert pipeline."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.services.wazuh_adapter import (
    WazuhAlert,
    normalize_wazuh_alerts,
)
from correlation.correlator import correlate, IncidentGroup
from correlation.hypothesis import build_hypothesis
from correlation.mitre_mapper import map_techniques
from correlation.timeline_builder import build_timeline
from detection import EventType, NormalizedEvent
from detection.engine import DetectionEngine
from tests.fixtures.wazuh_alerts import (
    account_compromise_scenario,
    brute_force_scenario,
    full_attack_scenario,
    ssh_auth_failure,
    ssh_auth_success,
)


def _normalize_fixtures(raw_alerts):
    alerts = [WazuhAlert.model_validate(r) for r in raw_alerts]
    return normalize_wazuh_alerts(alerts)


class TestDetectionCompatibility:
    def test_brute_force_detected(self):
        events = _normalize_fixtures(brute_force_scenario(count=7, interval_seconds=30))
        engine = DetectionEngine()
        alerts = engine.run(events)

        assert len(alerts) >= 1
        bf_alerts = [a for a in alerts if a.rule_name == "BRUTE_FORCE"]
        assert len(bf_alerts) >= 1

    def test_account_compromise_detected(self):
        events = _normalize_fixtures(
            account_compromise_scenario(failure_count=5, interval_seconds=20)
        )
        engine = DetectionEngine()
        alerts = engine.run(events)

        compromise_alerts = [a for a in alerts if a.rule_name == "ACCOUNT_COMPROMISE"]
        assert len(compromise_alerts) >= 1

    def test_all_events_have_correct_type(self):
        events = _normalize_fixtures(
            account_compromise_scenario(failure_count=3, interval_seconds=10)
        )
        failures = [e for e in events if e.event_type == EventType.AUTH_FAILURE]
        successes = [e for e in events if e.event_type == EventType.AUTH_SUCCESS]
        assert len(failures) == 3
        assert len(successes) == 1

    def test_below_threshold_no_alert(self):
        events = _normalize_fixtures(brute_force_scenario(count=2))
        engine = DetectionEngine()
        alerts = engine.run(events)
        bf_alerts = [a for a in alerts if a.rule_name == "BRUTE_FORCE"]
        assert len(bf_alerts) == 0


class TestCorrelationCompatibility:
    def test_brute_force_correlates(self):
        events = _normalize_fixtures(brute_force_scenario(count=7, interval_seconds=30))
        engine = DetectionEngine()
        alerts = engine.run(events)
        groups = correlate(alerts, events)

        assert len(groups) >= 1
        group = groups[0]
        assert group.source_ip == "192.168.1.100"
        assert group.username == "admin"

    def test_account_compromise_correlates(self):
        events = _normalize_fixtures(
            account_compromise_scenario(failure_count=5, interval_seconds=20)
        )
        engine = DetectionEngine()
        alerts = engine.run(events)
        groups = correlate(alerts, events)

        assert len(groups) >= 1
        group = groups[0]
        assert len(group.all_event_ids) > 0


class TestFullPipeline:
    def _run_full_pipeline(self, raw_alerts):
        events = _normalize_fixtures(raw_alerts)
        engine = DetectionEngine()
        alerts = engine.run(events)

        if not alerts:
            return None, None, None, None

        groups = correlate(alerts, events)
        if not groups:
            return None, None, None, None

        group = groups[0]
        timeline = build_timeline(events, set(group.all_event_ids))
        hypothesis = build_hypothesis(group, timeline)
        techniques = map_techniques(hypothesis["classification"])

        return group, timeline, hypothesis, techniques

    def test_brute_force_pipeline(self):
        group, timeline, hypothesis, techniques = self._run_full_pipeline(
            brute_force_scenario(count=7, interval_seconds=30)
        )
        assert group is not None
        assert hypothesis["classification"] == "BRUTE_FORCE"
        assert len(timeline) > 0
        assert len(techniques) > 0
        assert any(t["technique_id"] == "T1110" for t in techniques)

    def test_account_compromise_pipeline(self):
        group, timeline, hypothesis, techniques = self._run_full_pipeline(
            account_compromise_scenario(failure_count=5, interval_seconds=20)
        )
        assert group is not None
        assert hypothesis["classification"] in (
            "ACCOUNT_COMPROMISE",
            "ACCOUNT_COMPROMISE_WITH_ESCALATION",
        )

    def test_full_attack_pipeline(self):
        group, timeline, hypothesis, techniques = self._run_full_pipeline(
            full_attack_scenario(failure_count=5)
        )
        assert group is not None
        assert "ESCALATION" in hypothesis["classification"] or "COMPROMISE" in hypothesis["classification"]
        tech_ids = {t["technique_id"] for t in techniques}
        assert "T1110" in tech_ids

    def test_provenance_preserved_through_pipeline(self):
        events = _normalize_fixtures(brute_force_scenario(count=7, interval_seconds=30))

        for event in events:
            assert event.metadata["source_type"] == "wazuh"
            assert "wazuh_rule_id" in event.metadata
            assert "wazuh_agent_id" in event.metadata
            assert "wazuh_raw" in event.metadata
            assert "wazuh_decoder" in event.metadata

        engine = DetectionEngine()
        alerts = engine.run(events)
        assert len(alerts) > 0

        groups = correlate(alerts, events)
        assert len(groups) > 0

        event_map = {e.id: e for e in events}
        for eid in groups[0].all_event_ids:
            event = event_map[eid]
            assert event.metadata["source_type"] == "wazuh"
