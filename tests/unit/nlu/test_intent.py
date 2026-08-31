from ai.nlu.intent import Intent, classify_intent


class TestClassifyIntent:
    def test_search_events(self):
        assert classify_intent("show me failed logins from 10.0.0.5") == Intent.SEARCH_EVENTS

    def test_count(self):
        assert classify_intent("how many failed logins were there") == Intent.COUNT

    def test_timeline(self):
        assert classify_intent("walk me through the attack timeline") == Intent.TIMELINE

    def test_mitre_lookup(self):
        assert classify_intent("what MITRE ATT&CK techniques were used") == Intent.MITRE_LOOKUP

    def test_recommend_actions(self):
        assert classify_intent("what should I do about this incident") == Intent.RECOMMEND_ACTIONS

    def test_incident_summary(self):
        assert classify_intent("summarize the incident") == Intent.INCIDENT_SUMMARY

    def test_unknown(self):
        assert classify_intent("hello there") == Intent.UNKNOWN

    def test_priority_count_over_search(self):
        # "how many" + "show me" both present — count is more specific, should win
        text = "how many events can you show me from 10.0.0.5"
        assert classify_intent(text) == Intent.COUNT

    # --- New tests: ambiguous/vague inputs ---

    def test_vague_show_me_stuff(self):
        # "show" triggers SEARCH_EVENTS, but translate() will catch the ambiguity
        assert classify_intent("show me stuff") == Intent.SEARCH_EVENTS

    def test_anything_suspicious(self):
        assert classify_intent("anything suspicious?") == Intent.UNKNOWN

    def test_what_happened_is_incident_summary(self):
        assert classify_intent("what happened?") == Intent.INCIDENT_SUMMARY

    def test_show_attacks(self):
        # "show" triggers SEARCH_EVENTS
        assert classify_intent("show attacks") == Intent.SEARCH_EVENTS

    # --- New test: edge case empty-ish ---

    def test_single_word_unknown(self):
        assert classify_intent("banana") == Intent.UNKNOWN
