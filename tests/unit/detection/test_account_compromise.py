import uuid
from datetime import datetime, timedelta, timezone

from detection import EventType, Severity
from detection.rules.account_compromise import AccountCompromiseRule
from detection import NormalizedEvent

BASE = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
IP = "10.0.0.5"
USER = "john"


def _failure(offset: float, ip: str = IP, user: str = USER) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid.uuid4(), timestamp=BASE + timedelta(seconds=offset),
        event_type=EventType.AUTH_FAILURE, source_ip=ip, username=user,
        raw_log="fail", description="fail",
    )


def _success(offset: float, ip: str = IP, user: str = USER) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid.uuid4(), timestamp=BASE + timedelta(seconds=offset),
        event_type=EventType.AUTH_SUCCESS, source_ip=ip, username=user,
        raw_log="success", description="success",
    )


class TestAccountCompromiseRule:
    rule = AccountCompromiseRule()

    def _run(self, events):
        return self.rule.evaluate(sorted(events, key=lambda e: e.timestamp), {})

    def test_no_alert_without_success(self):
        events = [_failure(i * 10) for i in range(5)]
        assert self._run(events) == []

    def test_no_alert_with_success_but_only_2_failures(self):
        events = [_failure(i * 10) for i in range(2)] + [_success(30)]
        assert self._run(events) == []

    def test_fires_with_3_failures_then_success(self):
        events = [_failure(i * 10) for i in range(3)] + [_success(40)]
        alerts = self._run(events)
        assert len(alerts) == 1
        assert alerts[0].rule_name == "ACCOUNT_COMPROMISE"

    def test_severity_always_at_least_high(self):
        events = [_failure(i * 10) for i in range(5)] + [_success(60)]
        alerts = self._run(events)
        assert alerts[0].severity == Severity.HIGH

    def test_confidence_increases_with_more_failures(self):
        few_fail = [_failure(i * 10) for i in range(3)] + [_success(40)]
        many_fail = [_failure(i * 10) for i in range(12)] + [_success(130)]
        c_few = self._run(few_fail)[0].confidence
        c_many = self._run(many_fail)[0].confidence
        assert c_many > c_few

    def test_success_outside_grace_period_no_alert(self):
        events = [_failure(i * 10) for i in range(3)] + [_success(60 * 40)]
        assert self._run(events) == []

    def test_compromise_event_id_in_metadata(self):
        success_event = _success(50)
        events = [_failure(i * 10) for i in range(4)] + [success_event]
        alerts = self._run(events)
        assert str(success_event.id) == alerts[0].metadata["compromise_event_id"]

    def test_different_users_separate_alerts(self):
        alice = [_failure(i * 10, user="alice") for i in range(4)] + [_success(50, user="alice")]
        bob   = [_failure(i * 10, user="bob") for i in range(4)] + [_success(50, user="bob")]
        alerts = self._run(alice + bob)
        assert len(alerts) == 2
