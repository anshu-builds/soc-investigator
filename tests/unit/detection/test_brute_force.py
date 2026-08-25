import uuid
from datetime import datetime, timedelta, timezone

# pyrefly: ignore [missing-import]
import pytest

from detection import EventType, Severity
from detection.rules.brute_force import BruteForceRule
from detection import NormalizedEvent


def _make_failure(
    source_ip: str = "10.0.0.1",
    username: str = "admin",
    offset_seconds: float = 0,
    base_time: datetime | None = None,
) -> NormalizedEvent:
    if base_time is None:
        base_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        id=uuid.uuid4(),
        timestamp=base_time + timedelta(seconds=offset_seconds),
        event_type=EventType.AUTH_FAILURE,
        source_ip=source_ip,
        username=username,
        raw_log="test_log",
        description="Failed login",
    )


class TestBruteForceRule:
    rule = BruteForceRule()

    def _run(self, events):
        return self.rule.evaluate(sorted(events, key=lambda e: e.timestamp), {})

    def test_below_threshold_no_alert(self):
        events = [_make_failure(offset_seconds=i * 30) for i in range(4)]
        alerts = self._run(events)
        assert len(alerts) == 0

    def test_exactly_threshold_fires(self):
        events = [_make_failure(offset_seconds=i * 30) for i in range(5)]
        alerts = self._run(events)
        assert len(alerts) == 1

    def test_above_threshold_fires(self):
        events = [_make_failure(offset_seconds=i * 10) for i in range(10)]
        alerts = self._run(events)
        assert len(alerts) == 1

    def test_medium_severity_5_to_9(self):
        events = [_make_failure(offset_seconds=i * 30) for i in range(6)]
        alerts = self._run(events)
        assert alerts[0].severity == Severity.MEDIUM

    def test_high_severity_10_to_19(self):
        events = [_make_failure(offset_seconds=i * 30) for i in range(12)]
        alerts = self._run(events)
        assert alerts[0].severity == Severity.HIGH

    def test_critical_severity_20_plus(self):
        events = [_make_failure(offset_seconds=i * 10) for i in range(22)]
        alerts = self._run(events)
        assert alerts[0].severity == Severity.CRITICAL

    def test_critical_automated_fast_attack(self):
        events = [_make_failure(offset_seconds=i * 0.5) for i in range(8)]
        alerts = self._run(events)
        assert alerts[0].severity == Severity.CRITICAL

    def test_confidence_increases_with_more_failures(self):
        events_5 = [_make_failure(offset_seconds=i * 30) for i in range(5)]
        events_15 = [_make_failure(offset_seconds=i * 30) for i in range(15)]
        alerts_5 = self._run(events_5)
        alerts_15 = self._run(events_15)
        assert alerts_5[0].confidence < alerts_15[0].confidence

    def test_confidence_capped_at_0_95(self):
        events = [_make_failure(offset_seconds=i * 10) for i in range(50)]
        alerts = self._run(events)
        assert alerts[0].confidence <= 0.95

    def test_confidence_base_at_least_0_6(self):
        events = [_make_failure(offset_seconds=i * 30) for i in range(5)]
        alerts = self._run(events)
        assert alerts[0].confidence >= 0.60

    def test_different_users_separate_alerts(self):
        events = (
            [_make_failure(username="alice", offset_seconds=i * 10) for i in range(6)]
            + [_make_failure(username="bob", offset_seconds=i * 10) for i in range(6)]
        )
        alerts = self._run(events)
        assert len(alerts) == 2

    def test_different_ips_separate_alerts(self):
        events = (
            [_make_failure(source_ip="10.0.0.1", offset_seconds=i * 10) for i in range(6)]
            + [_make_failure(source_ip="10.0.0.2", offset_seconds=i * 10) for i in range(6)]
        )
        alerts = self._run(events)
        assert len(alerts) == 2

    def test_outside_time_window_no_alert(self):
        events = [_make_failure(offset_seconds=i * 150) for i in range(5)]
        alerts = self._run(events)
        assert len(alerts) == 0

    def test_alert_has_correct_metadata(self):
        events = [_make_failure(offset_seconds=i * 10) for i in range(7)]
        alerts = self._run(events)
        assert alerts[0].metadata["failed_count"] == 7
        assert alerts[0].metadata["source_ip"] == "10.0.0.1"
        assert alerts[0].metadata["username"] == "admin"
