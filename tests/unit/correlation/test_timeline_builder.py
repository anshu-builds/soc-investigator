import uuid
from datetime import datetime, timedelta

from detection import AttackPhase, EventType, NormalizedEvent
from correlation.timeline_builder import build_timeline


class TestTimelineBuilder:

    def make_event(
        self,
        minutes: int,
        event_type: EventType,
        username: str = "ankit",
        source_ip: str = "192.168.1.10",
        hostname: str = "host-1",
        description: str = "",
        metadata=None,
    ) -> NormalizedEvent:
        base_time = datetime(2026, 8, 30, 10, 0, 0)

        return NormalizedEvent(
            id=uuid.uuid4(),
            timestamp=base_time + timedelta(minutes=minutes),
            event_type=event_type,
            source_ip=source_ip,
            raw_log=f"raw log for {event_type.value}",
            description=description,
            username=username,
            hostname=hostname,
            metadata=metadata or {},
        )

    def test_only_incident_events_are_included(self):
        event1 = self.make_event(0, EventType.AUTH_FAILURE)
        event2 = self.make_event(1, EventType.AUTH_SUCCESS)
        event3 = self.make_event(2, EventType.PRIV_CHANGE)

        timeline = build_timeline(
            [event1, event2, event3],
            {event1.id, event3.id},
        )

        assert len(timeline) == 2
        assert timeline[0].event_id == event1.id
        assert timeline[1].event_id == event3.id

    def test_events_are_sorted_by_timestamp(self):
        late_event = self.make_event(10, EventType.PRIV_CHANGE)
        early_event = self.make_event(0, EventType.AUTH_FAILURE)
        middle_event = self.make_event(5, EventType.AUTH_SUCCESS)

        timeline = build_timeline(
            [late_event, middle_event, early_event],
            {
                late_event.id,
                middle_event.id,
                early_event.id,
            },
        )

        timestamps = [entry.timestamp for entry in timeline]

        assert timestamps == sorted(timestamps)

    def test_sequence_order_starts_at_one(self):
        event1 = self.make_event(0, EventType.AUTH_FAILURE)
        event2 = self.make_event(1, EventType.AUTH_SUCCESS)

        timeline = build_timeline(
            [event1, event2],
            {event1.id, event2.id},
        )

        assert timeline[0].sequence_order == 1
        assert timeline[1].sequence_order == 2

    def test_event_types_map_to_correct_phases(self):
        failure = self.make_event(0, EventType.AUTH_FAILURE)
        success = self.make_event(1, EventType.AUTH_SUCCESS)
        privilege = self.make_event(2, EventType.PRIV_CHANGE)
        file_access = self.make_event(3, EventType.FILE_ACCESS)

        timeline = build_timeline(
            [failure, success, privilege, file_access],
            {
                failure.id,
                success.id,
                privilege.id,
                file_access.id,
            },
        )

        phases = [entry.phase for entry in timeline]

        assert phases == [
            AttackPhase.INITIAL_ACCESS,
            AttackPhase.COMPROMISE,
            AttackPhase.ESCALATION,
            AttackPhase.IMPACT,
        ]

    def test_first_auth_failure_is_pivotal(self):
        event1 = self.make_event(0, EventType.AUTH_FAILURE)
        event2 = self.make_event(1, EventType.AUTH_FAILURE)

        timeline = build_timeline(
            [event1, event2],
            {event1.id, event2.id},
        )

        assert timeline[0].is_pivotal is True
        assert timeline[1].is_pivotal is False

    def test_first_auth_success_is_pivotal(self):
        event1 = self.make_event(0, EventType.AUTH_SUCCESS)
        event2 = self.make_event(1, EventType.AUTH_SUCCESS)

        timeline = build_timeline(
            [event1, event2],
            {event1.id, event2.id},
        )

        assert timeline[0].is_pivotal is True
        assert timeline[1].is_pivotal is False

    def test_first_privilege_change_is_pivotal(self):
        event1 = self.make_event(0, EventType.PRIV_CHANGE)
        event2 = self.make_event(1, EventType.PRIV_CHANGE)

        timeline = build_timeline(
            [event1, event2],
            {event1.id, event2.id},
        )

        assert timeline[0].is_pivotal is True
        assert timeline[1].is_pivotal is False

    def test_auth_failure_description_contains_attempt_number(self):
        event = self.make_event(0, EventType.AUTH_FAILURE)

        timeline = build_timeline(
            [event],
            {event.id},
        )

        assert "Failed login attempt #1" in timeline[0].description

    def test_file_access_description_uses_file_path(self):
        event = self.make_event(
            0,
            EventType.FILE_ACCESS,
            metadata={"file_path": "/etc/shadow"},
        )

        timeline = build_timeline(
            [event],
            {event.id},
        )

        assert "/etc/shadow" in timeline[0].description

    def test_unknown_event_uses_unknown_phase(self):
        event = self.make_event(
            0,
            EventType.UNKNOWN,
            description="Unknown security activity",
        )

        timeline = build_timeline(
            [event],
            {event.id},
        )

        assert timeline[0].phase == AttackPhase.UNKNOWN
        assert timeline[0].description == "Unknown security activity"

    def test_empty_incident_event_ids_returns_empty_timeline(self):
        event = self.make_event(0, EventType.AUTH_FAILURE)

        timeline = build_timeline(
            [event],
            set(),
        )

        assert timeline == []