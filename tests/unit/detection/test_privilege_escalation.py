import uuid
from datetime import datetime, timedelta, timezone

from detection import EventType, Severity
from detection.rules.privilege_escalation import PrivilegeEscalationRule
from detection import NormalizedEvent

BASE = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
IP = "10.0.0.5"
USER = "admin"


def _event(offset: float, ev_type: EventType, ip: str = IP, user: str = USER) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid.uuid4(), timestamp=BASE + timedelta(minutes=offset),
        event_type=ev_type, source_ip=ip, username=user,
        raw_log=ev_type.value, description=ev_type.value,
    )


class TestPrivilegeEscalationRule:
    rule = PrivilegeEscalationRule()

    def _run(self, events):
        return self.rule.evaluate(sorted(events, key=lambda e: e.timestamp), {})

    def test_no_alert_without_priv_change(self):
        events = [_event(0, EventType.AUTH_SUCCESS)]
        assert self._run(events) == []

    def test_alert_on_priv_change_alone(self):
        events = [_event(0, EventType.PRIV_CHANGE)]
        alerts = self._run(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH

    def test_alert_with_preceding_auth_success(self):
        events = [
            _event(0, EventType.AUTH_SUCCESS),
            _event(10, EventType.PRIV_CHANGE),
        ]
        alerts = self._run(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.CRITICAL
        assert "auth_event_id" in alerts[0].metadata

    def test_auth_success_outside_window(self):
        events = [
            _event(0, EventType.AUTH_SUCCESS),
            _event(40, EventType.PRIV_CHANGE),
        ]
        alerts = self._run(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH

    def test_multiple_priv_changes_grouped(self):
        events = [
            _event(0, EventType.AUTH_SUCCESS),
            _event(10, EventType.PRIV_CHANGE),
            _event(15, EventType.PRIV_CHANGE),
        ]
        alerts = self._run(events)
        assert len(alerts) == 1
        assert len(alerts[0].contributing_event_ids) == 3

    def test_different_users_separate_alerts(self):
        events = [
            _event(0, EventType.PRIV_CHANGE, user="alice"),
            _event(5, EventType.PRIV_CHANGE, user="bob"),
        ]
        alerts = self._run(events)
        assert len(alerts) == 2
