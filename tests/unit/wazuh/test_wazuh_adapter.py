"""Unit tests for the Wazuh → NormalizedEvent adapter.

All tests are fixture-based.  No running Wazuh Manager is required.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.services.wazuh_adapter import (
    WazuhAlert,
    WazuhIngestionRequest,
    _map_severity,
    compute_dedup_hash,
    map_event_type,
    normalize_wazuh_alert,
    normalize_wazuh_alerts,
)
from detection import EventType, NormalizedEvent
from tests.fixtures.wazuh_alerts import (
    alert_with_data_status_only,
    alert_with_no_groups_but_description_keywords,
    brute_force_scenario,
    file_integrity_alert,
    minimal_alert,
    ssh_auth_failure,
    ssh_auth_success,
    sudo_privilege_escalation,
)


# ---------------------------------------------------------------------------
# EventType mapping — Priority 1: rule.groups
# ---------------------------------------------------------------------------


class TestEventTypeMappingByGroups:
    """Semantic mapping from rule.groups → EventType."""

    def test_auth_failure_from_groups(self):
        alert = WazuhAlert.model_validate(ssh_auth_failure())
        assert map_event_type(alert) == EventType.AUTH_FAILURE

    def test_auth_success_from_groups(self):
        alert = WazuhAlert.model_validate(ssh_auth_success())
        assert map_event_type(alert) == EventType.AUTH_SUCCESS

    def test_priv_change_from_groups(self):
        alert = WazuhAlert.model_validate(sudo_privilege_escalation())
        assert map_event_type(alert) == EventType.PRIV_CHANGE

    def test_file_access_from_groups(self):
        alert = WazuhAlert.model_validate(file_integrity_alert())
        assert map_event_type(alert) == EventType.FILE_ACCESS

    def test_unknown_when_no_classification(self):
        alert = WazuhAlert.model_validate(minimal_alert())
        assert map_event_type(alert) == EventType.UNKNOWN


# ---------------------------------------------------------------------------
# EventType mapping — Priority 2: data fields
# ---------------------------------------------------------------------------


class TestEventTypeMappingByData:
    """Fallback classification from data field signatures."""

    def test_auth_failure_from_data_status(self):
        alert = WazuhAlert.model_validate(alert_with_data_status_only())
        assert map_event_type(alert) == EventType.AUTH_FAILURE

    def test_auth_success_from_data_status(self):
        raw = alert_with_data_status_only()
        raw["rule"]["groups"] = ["generic"]
        raw["data"]["status"] = "accepted"
        alert = WazuhAlert.model_validate(raw)
        assert map_event_type(alert) == EventType.AUTH_SUCCESS


# ---------------------------------------------------------------------------
# EventType mapping — Priority 4: description keywords
# ---------------------------------------------------------------------------


class TestEventTypeMappingByDescription:
    """Fallback classification from rule.description keywords."""

    def test_auth_failure_from_description(self):
        alert = WazuhAlert.model_validate(
            alert_with_no_groups_but_description_keywords()
        )
        assert map_event_type(alert) == EventType.AUTH_FAILURE


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_critical_level_12(self):
        assert _map_severity(12) == "CRITICAL"

    def test_critical_level_16(self):
        assert _map_severity(16) == "CRITICAL"

    def test_high_level_8(self):
        assert _map_severity(8) == "HIGH"

    def test_high_level_11(self):
        assert _map_severity(11) == "HIGH"

    def test_medium_level_5(self):
        assert _map_severity(5) == "MEDIUM"

    def test_medium_level_7(self):
        assert _map_severity(7) == "MEDIUM"

    def test_low_level_0(self):
        assert _map_severity(0) == "LOW"

    def test_low_level_4(self):
        assert _map_severity(4) == "LOW"


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestTimestampParsing:
    def test_valid_iso_timestamp(self):
        alert = WazuhAlert.model_validate(ssh_auth_failure())
        event = normalize_wazuh_alert(alert)
        assert event.timestamp.tzinfo is not None
        assert event.timestamp.year == 2025

    def test_missing_full_log_still_normalizes(self):
        raw = minimal_alert()
        alert = WazuhAlert.model_validate(raw)
        event = normalize_wazuh_alert(alert)
        assert isinstance(event.timestamp, datetime)


# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------


class TestFieldMapping:
    def test_source_ip_from_data_srcip(self):
        alert = WazuhAlert.model_validate(ssh_auth_failure(src_ip="10.20.30.40"))
        event = normalize_wazuh_alert(alert)
        assert event.source_ip == "10.20.30.40"

    def test_source_ip_fallback_to_agent_ip(self):
        raw = minimal_alert()
        raw["agent"]["ip"] = "10.0.0.99"
        alert = WazuhAlert.model_validate(raw)
        event = normalize_wazuh_alert(alert)
        assert event.source_ip == "10.0.0.99"

    def test_source_ip_fallback_to_zero(self):
        raw = minimal_alert()
        alert = WazuhAlert.model_validate(raw)
        event = normalize_wazuh_alert(alert)
        assert event.source_ip == "0.0.0.0"

    def test_username_from_data_srcuser(self):
        alert = WazuhAlert.model_validate(ssh_auth_failure(user="testuser"))
        event = normalize_wazuh_alert(alert)
        assert event.username == "testuser"

    def test_username_none_when_absent(self):
        raw = minimal_alert()
        alert = WazuhAlert.model_validate(raw)
        event = normalize_wazuh_alert(alert)
        assert event.username is None

    def test_hostname_from_agent_name(self):
        alert = WazuhAlert.model_validate(
            ssh_auth_failure(agent_name="production-web-01")
        )
        event = normalize_wazuh_alert(alert)
        assert event.hostname == "production-web-01"

    def test_description_from_rule(self):
        alert = WazuhAlert.model_validate(ssh_auth_failure())
        event = normalize_wazuh_alert(alert)
        assert "login failed" in event.description.lower()

    def test_raw_log_from_full_log(self):
        alert = WazuhAlert.model_validate(ssh_auth_failure())
        event = normalize_wazuh_alert(alert)
        assert "sshd" in event.raw_log

    def test_raw_log_fallback_when_no_full_log(self):
        raw = minimal_alert()
        alert = WazuhAlert.model_validate(raw)
        event = normalize_wazuh_alert(alert)
        assert len(event.raw_log) > 0  # serialized alert JSON


# ---------------------------------------------------------------------------
# Provenance preservation
# ---------------------------------------------------------------------------


class TestProvenance:
    """Every normalized Wazuh event must carry complete provenance."""

    def _normalize(self, fixture_fn, **kwargs):
        alert = WazuhAlert.model_validate(fixture_fn(**kwargs))
        return normalize_wazuh_alert(alert)

    def test_source_type(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["source_type"] == "wazuh"

    def test_wazuh_rule_id(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["wazuh_rule_id"] == "5503"

    def test_wazuh_rule_level(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["wazuh_rule_level"] == 5

    def test_wazuh_rule_description(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["wazuh_rule_description"] == "User login failed."

    def test_wazuh_rule_groups(self):
        event = self._normalize(ssh_auth_failure)
        assert "authentication_failed" in event.metadata["wazuh_rule_groups"]

    def test_wazuh_agent_id(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["wazuh_agent_id"] == "001"

    def test_wazuh_agent_name(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["wazuh_agent_name"] == "web-server-01"

    def test_wazuh_decoder(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["wazuh_decoder"] == "sshd"

    def test_wazuh_mitre_when_present(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["wazuh_mitre"] is not None
        assert "T1110" in event.metadata["wazuh_mitre"]["id"]

    def test_wazuh_mitre_none_when_absent(self):
        event = self._normalize(file_integrity_alert)
        assert event.metadata["wazuh_mitre"] is None

    def test_wazuh_raw_is_complete(self):
        event = self._normalize(ssh_auth_failure)
        raw = event.metadata["wazuh_raw"]
        assert "rule" in raw
        assert "agent" in raw
        assert "timestamp" in raw

    def test_source_file_format(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["source_file"].startswith("wazuh://agent/")
        assert "/rule/" in event.metadata["source_file"]

    def test_severity_raw(self):
        event = self._normalize(ssh_auth_failure)
        assert event.metadata["severity_raw"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Deduplication hash
# ---------------------------------------------------------------------------


class TestDedup:
    def test_same_alert_produces_same_hash(self):
        raw = ssh_auth_failure()
        alert1 = WazuhAlert.model_validate(raw)
        alert2 = WazuhAlert.model_validate(raw)
        assert compute_dedup_hash(alert1) == compute_dedup_hash(alert2)

    def test_different_alerts_produce_different_hash(self):
        alert1 = WazuhAlert.model_validate(ssh_auth_failure(offset=0))
        alert2 = WazuhAlert.model_validate(ssh_auth_failure(offset=60))
        assert compute_dedup_hash(alert1) != compute_dedup_hash(alert2)


# ---------------------------------------------------------------------------
# Batch normalization
# ---------------------------------------------------------------------------


class TestBatchNormalization:
    def test_batch_normalizes_all_alerts(self):
        raws = brute_force_scenario(count=5)
        alerts = [WazuhAlert.model_validate(r) for r in raws]
        events = normalize_wazuh_alerts(alerts)
        assert len(events) == 5
        assert all(isinstance(e, NormalizedEvent) for e in events)
        assert all(e.event_type == EventType.AUTH_FAILURE for e in events)

    def test_each_event_has_unique_id(self):
        raws = brute_force_scenario(count=3)
        alerts = [WazuhAlert.model_validate(r) for r in raws]
        events = normalize_wazuh_alerts(alerts)
        ids = [e.id for e in events]
        assert len(set(ids)) == 3


# ---------------------------------------------------------------------------
# Pydantic validation
# ---------------------------------------------------------------------------


class TestPayloadValidation:
    def test_valid_alert_validates(self):
        alert = WazuhAlert.model_validate(ssh_auth_failure())
        assert alert.rule.id == "5503"

    def test_missing_rule_raises(self):
        with pytest.raises(Exception):
            WazuhAlert.model_validate({"timestamp": "2025-01-01T00:00:00+00:00", "agent": {"id": "1", "name": "h"}})

    def test_missing_timestamp_raises(self):
        raw = ssh_auth_failure()
        del raw["timestamp"]
        with pytest.raises(Exception):
            WazuhAlert.model_validate(raw)

    def test_empty_timestamp_raises(self):
        raw = ssh_auth_failure()
        raw["timestamp"] = "  "
        with pytest.raises(Exception):
            WazuhAlert.model_validate(raw)

    def test_rule_level_out_of_range_raises(self):
        raw = ssh_auth_failure()
        raw["rule"]["level"] = 20
        with pytest.raises(Exception):
            WazuhAlert.model_validate(raw)

    def test_ingestion_request_empty_alerts_raises(self):
        with pytest.raises(Exception):
            WazuhIngestionRequest.model_validate({"alerts": []})
