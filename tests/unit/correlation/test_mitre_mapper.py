from correlation.hypothesis import (
    ATTACK_TYPE_ACCOUNT_COMPROMISE,
    ATTACK_TYPE_ACCOUNT_COMPROMISE_WITH_ESCALATION,
    ATTACK_TYPE_BRUTE_FORCE,
    ATTACK_TYPE_PRIVILEGE_ESCALATION_ONLY,
)
from correlation.mitre_mapper import map_techniques


class TestMitreMapper:

    def test_brute_force_mapping(self):
        techniques = map_techniques(
            ATTACK_TYPE_BRUTE_FORCE
        )

        technique_ids = [
            technique["technique_id"]
            for technique in techniques
        ]

        assert "T1110" in technique_ids
        assert len(techniques) == 2

    def test_account_compromise_mapping(self):
        techniques = map_techniques(
            ATTACK_TYPE_ACCOUNT_COMPROMISE
        )

        technique_ids = [
            technique["technique_id"]
            for technique in techniques
        ]

        assert "T1110" in technique_ids
        assert "T1078" in technique_ids

    def test_account_compromise_with_escalation_mapping(self):
        techniques = map_techniques(
            ATTACK_TYPE_ACCOUNT_COMPROMISE_WITH_ESCALATION
        )

        technique_ids = [
            technique["technique_id"]
            for technique in techniques
        ]

        sub_technique_ids = [
            technique["sub_technique_id"]
            for technique in techniques
        ]

        assert "T1110" in technique_ids
        assert "T1078" in technique_ids
        assert "T1078.003" in sub_technique_ids

    def test_privilege_escalation_only_mapping(self):
        techniques = map_techniques(
            ATTACK_TYPE_PRIVILEGE_ESCALATION_ONLY
        )

        technique_ids = [
            technique["technique_id"]
            for technique in techniques
        ]

        assert "T1078" in technique_ids

    def test_all_mappings_have_required_fields(self):
        techniques = map_techniques(
            ATTACK_TYPE_BRUTE_FORCE
        )

        required_fields = {
            "technique_id",
            "technique_name",
            "tactic",
            "sub_technique_id",
            "sub_technique_name",
            "url",
            "confidence",
            "mapping_source",
        }

        for technique in techniques:
            assert required_fields.issubset(
                technique.keys()
            )

    def test_mapping_source_is_rule_based(self):
        techniques = map_techniques(
            ATTACK_TYPE_BRUTE_FORCE
        )

        for technique in techniques:
            assert technique["mapping_source"] == "RULE_BASED"

    def test_unknown_attack_type_uses_default_mapping(self):
        techniques = map_techniques(
            "UNKNOWN_ATTACK_TYPE"
        )

        assert len(techniques) == 1
        assert techniques[0]["technique_id"] == "T1110"