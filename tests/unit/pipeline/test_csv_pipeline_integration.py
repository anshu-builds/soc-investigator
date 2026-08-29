"""Integration tests for the CSV log ingestion and detection pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.services.log_service import parse_upload
from correlation.correlator import correlate
from correlation.hypothesis import build_hypothesis
from correlation.mitre_mapper import map_techniques
from correlation.timeline_builder import build_timeline
from detection.engine import DetectionEngine
from detection.normalizer import normalize_batch

SAMPLE_CSV_PATH = Path(__file__).resolve().parents[3] / "datasets" / "samples" / "brute_force_sample.csv"


class TestCSVPipelineIntegration:
    def test_brute_force_csv_full_pipeline(self):
        assert SAMPLE_CSV_PATH.exists(), f"Sample CSV not found at {SAMPLE_CSV_PATH}"

        with open(SAMPLE_CSV_PATH, "rb") as f:
            content = f.read()

        # Step 1: Parse upload
        raw_rows = parse_upload(content, "brute_force_sample.csv")
        assert len(raw_rows) == 20

        # Step 2: Normalize batch
        normalized_events = normalize_batch(raw_rows, "brute_force_sample.csv")
        assert len(normalized_events) == 20

        # Step 3: Run Detection Engine
        engine = DetectionEngine()
        alerts = engine.run(normalized_events)
        assert len(alerts) >= 1
        bf_alerts = [a for a in alerts if a.rule_name == "BRUTE_FORCE"]
        assert len(bf_alerts) >= 1
        alert = bf_alerts[0]
        assert alert.metadata["source_ip"] == "192.168.1.55"
        assert alert.metadata["username"] == "admin"
        assert alert.metadata["failed_count"] >= 10

        # Step 4: Correlation
        incident_groups = correlate(alerts, normalized_events)
        assert len(incident_groups) >= 1
        group = incident_groups[0]
        assert group.source_ip == "192.168.1.55"
        assert group.username == "admin"

        # Step 5: Timeline, Hypothesis, and MITRE mapping
        timeline = build_timeline(normalized_events, set(group.all_event_ids))
        hypothesis = build_hypothesis(group, timeline)
        techniques = map_techniques(hypothesis["classification"])

        assert hypothesis["classification"] == "BRUTE_FORCE"
        assert len(timeline) > 0
        assert len(techniques) > 0
        tech_ids = {t["technique_id"] for t in techniques}
        assert "T1110" in tech_ids
