import uuid
from datetime import datetime, timedelta, timezone

from detection import Alert, Severity, NormalizedEvent, EventType
from correlation.correlator import correlate

BASE = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
IP = "10.0.0.5"
USER = "admin"


def _event(event_id: uuid.UUID, offset: float) -> NormalizedEvent:
    return NormalizedEvent(
        id=event_id,
        timestamp=BASE + timedelta(minutes=offset),
        event_type=EventType.UNKNOWN,
        source_ip=IP,
        raw_log="",
        description=""
    )


def _alert(offset: float, rule: str, ip: str = IP, user: str = USER) -> tuple[Alert, NormalizedEvent]:
    eid = uuid.uuid4()
    ev = _event(eid, offset)
    al = Alert(
        id=uuid.uuid4(), rule_name=rule, 
        severity=Severity.HIGH, confidence=0.8, description=rule,
        contributing_event_ids=[eid], metadata={"source_ip": ip, "username": user},
    )
    al.detected_at = BASE + timedelta(days=365)
    return al, ev


class TestCorrelator:
    def test_correlate_single_alert(self):
        a1, e1 = _alert(0, "BRUTE_FORCE")
        groups = correlate([a1], [e1])
        assert len(groups) == 1
        assert groups[0].source_ip == IP
        assert groups[0].username == USER
        assert groups[0].first_seen == e1.timestamp
        assert groups[0].last_seen == e1.timestamp

    def test_correlate_multiple_alerts_same_user_within_window(self):
        a1, e1 = _alert(0, "BRUTE_FORCE")
        a2, e2 = _alert(30, "ACCOUNT_COMPROMISE")
        a3, e3 = _alert(45, "PRIVILEGE_ESCALATION")
        groups = correlate([a1, a2, a3], [e1, e2, e3])
        assert len(groups) == 1
        assert len(groups[0].alerts) == 3
        assert groups[0].first_seen == e1.timestamp
        assert groups[0].last_seen == e3.timestamp

    def test_correlate_alerts_outside_window(self):
        a1, e1 = _alert(0, "BRUTE_FORCE")
        a2, e2 = _alert(70, "ACCOUNT_COMPROMISE")
        groups = correlate([a1, a2], [e1, e2])
        assert len(groups) == 2

    def test_correlate_different_entities(self):
        a1, e1 = _alert(0, "BRUTE_FORCE", user="alice")
        a2, e2 = _alert(10, "BRUTE_FORCE", user="bob")
        groups = correlate([a1, a2], [e1, e2])
        assert len(groups) == 2

    def test_severity_and_confidence_aggregation(self):
        e1, e2 = uuid.uuid4(), uuid.uuid4()
        ne1 = _event(e1, 0)
        ne2 = _event(e2, 10)
        
        alerts = [
            Alert(
                id=uuid.uuid4(), rule_name="BRUTE_FORCE",
                severity=Severity.LOW, confidence=0.5, description="",
                contributing_event_ids=[e1], metadata={"username": USER}
            ),
            Alert(
                id=uuid.uuid4(), rule_name="ACCOUNT_COMPROMISE",
                severity=Severity.CRITICAL, confidence=0.9, description="",
                contributing_event_ids=[e2], metadata={"username": USER}
            )
        ]
        groups = correlate(alerts, [ne1, ne2])
        assert len(groups) == 1
        assert groups[0].overall_severity == Severity.CRITICAL
        assert groups[0].overall_confidence == 0.678

    def test_all_event_ids_aggregated(self):
        e1, e2, e3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        alerts = [
            Alert(
                id=uuid.uuid4(), rule_name="R1",
                severity=Severity.LOW, confidence=0.5, description="",
                contributing_event_ids=[e1, e2], metadata={"username": USER}
            ),
            Alert(
                id=uuid.uuid4(), rule_name="R2",
                severity=Severity.LOW, confidence=0.5, description="",
                contributing_event_ids=[e3], metadata={"username": USER}
            )
        ]
        groups = correlate(alerts, [])
        assert len(groups) == 1
        assert set(groups[0].all_event_ids) == {e1, e2, e3}

    def test_alert_processing_time_does_not_affect_incident_time(self):
        event_time = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        eid = uuid.uuid4()
        ne = NormalizedEvent(
            id=eid, timestamp=event_time, event_type=EventType.UNKNOWN,
            source_ip=IP, raw_log="", description=""
        )

        detection_time = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
        al = Alert(
            id=uuid.uuid4(), rule_name="TEST_RULE",
            severity=Severity.HIGH, confidence=0.9, description="",
            contributing_event_ids=[eid], metadata={"username": USER},
            detected_at=detection_time
        )

        groups = correlate([al], [ne])
        
        assert len(groups) == 1
        assert groups[0].first_seen == event_time
        assert groups[0].last_seen == event_time
        assert groups[0].alerts[0].detected_at == detection_time
