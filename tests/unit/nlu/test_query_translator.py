from ai.nlu.intent import Intent
from ai.nlu.query_translator import build_query, translate


class TestTranslate:
    def test_unknown_intent_asks_clarification(self):
        result = translate("hello there")
        assert result.needs_clarification is True
        assert result.query_spec is None

    def test_empty_text_asks_clarification(self):
        result = translate("")
        assert result.needs_clarification is True

    def test_whitespace_only_asks_clarification(self):
        result = translate("   ")
        assert result.needs_clarification is True

    def test_search_events_without_entities_asks_clarification(self):
        # "show me events" with no IP/user/host/time is too broad to run
        result = translate("show me events")
        assert result.needs_clarification is True
        assert "which" in (result.clarification_question or "").lower()

    def test_search_events_with_ip_resolves(self):
        result = translate("show failed logins from 10.10.5.200")
        assert result.needs_clarification is False
        assert result.query_spec is not None
        assert result.query_spec.intent == Intent.SEARCH_EVENTS
        assert result.query_spec.entities.ips == ["10.10.5.200"]

    def test_incident_summary_does_not_require_entities(self):
        # "any open incidents" is a valid, bounded query even with no entities
        result = translate("summarize any active incidents")
        assert result.needs_clarification is False
        assert result.query_spec.target == "incidents"

    def test_count_intent_resolves_target(self):
        result = translate("how many failed logins from 10.0.0.5 today")
        assert result.needs_clarification is False
        assert result.query_spec.intent == Intent.COUNT
        assert result.query_spec.target == "security_events"

    # --- New: COUNT + severity routes to incidents ---

    def test_count_critical_incidents_routes_to_incidents(self):
        result = translate("how many critical incidents are there")
        assert result.needs_clarification is False
        assert result.query_spec.intent == Intent.COUNT
        assert result.query_spec.target == "incidents"

    def test_count_high_severity_routes_to_incidents(self):
        result = translate("how many high severity incidents occurred today")
        assert result.needs_clarification is False
        assert result.query_spec.target == "incidents"

    # --- New: ambiguous queries ---

    def test_show_me_stuff_asks_clarification(self):
        result = translate("show me stuff")
        assert result.needs_clarification is True

    def test_show_attacks_without_detail_asks_clarification(self):
        # "show attacks" → SEARCH_EVENTS but empty entities (no IP/user/host/time/event_type)
        # attack_types would be extracted if "brute force" etc. were present, but "attacks" alone is too vague
        result = translate("show attacks")
        assert result.needs_clarification is True

    def test_anything_suspicious_asks_clarification(self):
        result = translate("anything suspicious?")
        assert result.needs_clarification is True

    # --- New: security edge cases ---

    def test_sql_injection_attempt_does_not_resolve(self):
        result = translate("'; DROP TABLE security_events; --")
        # Should be UNKNOWN intent → clarification
        assert result.needs_clarification is True

    def test_very_long_input(self):
        result = translate("show " + "x" * 400)
        assert result.needs_clarification is True  # too broad, no entities


class TestBuildQuery:
    def test_events_query_filters_by_ip(self):
        result = translate("show failed logins from 10.10.5.200")
        stmt = build_query(result.query_spec)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "10.10.5.200" in compiled
        assert "source_ip" in compiled

    def test_events_query_filters_by_username(self):
        result = translate("show events for user sarah.miller")
        stmt = build_query(result.query_spec)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "sarah.miller" in compiled

    def test_count_query_uses_count_function(self):
        result = translate("how many events from 10.0.0.5")
        stmt = build_query(result.query_spec)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "count" in compiled.lower()

    def test_incidents_query_filters_by_severity(self):
        result = translate("show critical incidents")
        stmt = build_query(result.query_spec)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "CRITICAL" in compiled

    # --- New: incident count uses count() ---

    def test_incident_count_uses_count_function(self):
        result = translate("how many critical incidents are there")
        stmt = build_query(result.query_spec)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "count" in compiled.lower()
        assert "CRITICAL" in compiled
