from datetime import datetime, timezone

from ai.nlu.entities import extract_entities


NOW = datetime(2025, 8, 20, 12, 0, 0, tzinfo=timezone.utc)


class TestExtractEntities:
    def test_extracts_ip(self):
        e = extract_entities("show me failed logins from 10.10.5.200", now=NOW)
        assert e.ips == ["10.10.5.200"]

    def test_extracts_username_with_keyword(self):
        e = extract_entities("what did user sarah.miller do", now=NOW)
        assert "sarah.miller" in e.usernames

    def test_extracts_username_quoted(self):
        e = extract_entities("investigate 'admin' account activity", now=NOW)
        assert "admin" in e.usernames

    def test_does_not_confuse_ip_with_username(self):
        e = extract_entities("events from 10.10.5.200 for user admin", now=NOW)
        assert e.ips == ["10.10.5.200"]
        assert "admin" in e.usernames
        assert "10.10.5.200" not in e.usernames

    def test_extracts_event_type_brute_force(self):
        e = extract_entities("show brute force attempts", now=NOW)
        assert "AUTH_FAILURE" in e.event_types

    def test_extracts_event_type_priv_escalation(self):
        e = extract_entities("any privilege escalation activity", now=NOW)
        assert "PRIV_CHANGE" in e.event_types

    def test_extracts_relative_time_hours(self):
        e = extract_entities("failed logins in the last 24 hours", now=NOW)
        assert e.time_start is not None
        assert (NOW - e.time_start).total_seconds() == 24 * 3600
        assert e.time_end == NOW

    def test_extracts_relative_time_days(self):
        e = extract_entities("incidents from the past 3 days", now=NOW)
        assert (NOW - e.time_start).days == 3

    def test_extracts_today(self):
        e = extract_entities("what happened today", now=NOW)
        assert e.time_start == NOW.replace(hour=0, minute=0, second=0, microsecond=0)

    def test_extracts_severity(self):
        e = extract_entities("show critical incidents", now=NOW)
        assert "CRITICAL" in e.severities

    def test_extracts_attack_type(self):
        e = extract_entities("find brute force attacks", now=NOW)
        assert "BRUTE_FORCE" in e.attack_types

    def test_empty_text_yields_empty_entities(self):
        e = extract_entities("hello", now=NOW)
        assert e.is_empty()

    def test_multiple_entities_combined(self):
        e = extract_entities(
            "show failed logins from 10.10.5.200 for user admin in the last 2 hours",
            now=NOW,
        )
        assert e.ips == ["10.10.5.200"]
        assert "admin" in e.usernames
        assert "AUTH_FAILURE" in e.event_types
        assert e.time_start is not None

    # --- New tests: bare hostnames ---

    def test_extracts_bare_hostname_with_on_keyword(self):
        e = extract_entities("what happened on web-server-01", now=NOW)
        assert "web-server-01" in e.hostnames

    def test_extracts_bare_hostname_with_host_keyword(self):
        e = extract_entities("show events from host dc-controller-02", now=NOW)
        assert "dc-controller-02" in e.hostnames

    def test_extracts_fqdn_hostname(self):
        e = extract_entities("events from workstation-42.corp.local", now=NOW)
        assert any("workstation-42" in h for h in e.hostnames)

    # --- New tests: authentication failures keyword ---

    def test_extracts_authentication_failures(self):
        e = extract_entities("show authentication failures for user admin", now=NOW)
        assert "AUTH_FAILURE" in e.event_types
        assert "admin" in e.usernames

    def test_extracts_authentication_failure_singular(self):
        e = extract_entities("any authentication failure from 10.0.0.1", now=NOW)
        assert "AUTH_FAILURE" in e.event_types
        assert "10.0.0.1" in e.ips

    # --- New test: yesterday ---

    def test_extracts_yesterday(self):
        e = extract_entities("show brute-force attacks from yesterday", now=NOW)
        assert e.time_start is not None
        assert e.time_end is not None
        assert e.time_start.day == 19  # day before 20th

    # --- New test: multiple IPs ---

    def test_extracts_multiple_ips(self):
        e = extract_entities("show events from 10.0.0.1 and 192.168.1.100", now=NOW)
        assert "10.0.0.1" in e.ips
        assert "192.168.1.100" in e.ips

    # --- New test: for <username> without 'user' keyword ---

    def test_extracts_for_admin(self):
        e = extract_entities("Show authentication failures for admin.", now=NOW)
        assert "admin" in e.usernames
        assert "AUTH_FAILURE" in e.event_types

    def test_extracts_mitre_technique(self):
        e = extract_entities("Show incidents involving T1110", now=NOW)
        assert "T1110" in e.mitre_techniques
