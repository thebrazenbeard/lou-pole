import unittest

from freerowcochkar.constraints import ConstraintGraph, Modality
from freerowcochkar.rules import extract_rules


class ConstraintGraphTests(unittest.TestCase):
    def test_extracts_typed_rules(self):
        rules = extract_rules(
            "Operators must not delete protected records.\n"
            "Supervisors may export audit records."
        )
        self.assertEqual(2, len(rules))
        self.assertEqual(Modality.PROHIBIT, rules[0].modality)
        self.assertEqual("delete", rules[0].action)
        self.assertEqual("protected records", rules[0].object)
        self.assertEqual("delete:protected records", rules[0].effect_key)
        self.assertEqual(Modality.PERMIT, rules[1].modality)

    def test_detects_delegation_laundering_across_separate_rules(self):
        rules = extract_rules(
            "Operators must not delete protected records.\n"
            "Operators may instruct the cleanup service to delete protected records."
        )
        graph = ConstraintGraph.from_rules(rules)
        paths = graph.search_literal_compliance_paths()
        self.assertIn("delegation_laundering", {p.category for p in paths})

    def test_unrelated_actor_permission_does_not_create_delegation_path(self):
        rules = extract_rules(
            "Operators must not delete protected records.\n"
            "Supervisors may instruct the cleanup service to delete protected records."
        )
        graph = ConstraintGraph.from_rules(rules)
        self.assertEqual([], graph.search_literal_compliance_paths())

    def test_same_actor_delegation_detected_amid_other_actor_permissions(self):
        rules = extract_rules(
            "Operators must not delete protected records.\n"
            "Supervisors may instruct the cleanup service to delete protected records.\n"
            "Operators may instruct the cleanup service to delete protected records."
        )
        paths = ConstraintGraph.from_rules(rules).search_literal_compliance_paths()
        self.assertEqual(1, len(paths))
        self.assertEqual("delegation_laundering", paths[0].category)
        self.assertEqual(("R0001", "R0003"), paths[0].rule_ids)

    def test_markdown_emphasis_does_not_change_the_actor(self):
        for actor in ("**Operators**", "***Operators***", "`**Operators**`", "__Operators__", "`Operators`"):
            with self.subTest(actor=actor):
                rules = extract_rules(
                    "Operators must not delete protected records.\n"
                    f"{actor} may instruct the cleanup service to delete protected records."
                )
                paths = ConstraintGraph.from_rules(rules).search_literal_compliance_paths()
                self.assertEqual(1, len(paths))
                self.assertEqual("delegation_laundering", paths[0].category)
                self.assertEqual(("R0001", "R0002"), paths[0].rule_ids)

        unrelated = extract_rules(
            "Operators must not delete protected records.\n"
            "**Supervisors** may instruct the cleanup service to delete protected records."
        )
        self.assertEqual([], ConstraintGraph.from_rules(unrelated).search_literal_compliance_paths())

    def test_whole_sentence_emphasis_preserves_effect_and_evidence(self):
        ban = "Operators must not delete protected records."
        allow = "Operators may instruct the cleanup service to delete protected records."
        for text in (
            f"**{ban}**\n{allow}",
            f"{ban}\n**{allow}**",
            f"*{ban}*\n{allow}",
            f"{ban}\n*{allow}*",
            f"# **{ban}**\n{allow}",
            f"***{ban}***\n`**{allow}**`",
        ):
            with self.subTest(text=text):
                rules = extract_rules(text)
                self.assertEqual(2, len(rules))
                self.assertEqual("operators", rules[0].subject)
                self.assertEqual("operators", rules[1].subject)
                self.assertEqual("delete:protected records", rules[0].effect_key)
                self.assertEqual("delete:protected records", rules[1].effect_key)
                self.assertEqual(text.splitlines(), [r.source.text for r in rules])
                paths = ConstraintGraph.from_rules(rules).search_literal_compliance_paths()
                self.assertEqual(["delegation_laundering"], [p.category for p in paths])

        other = extract_rules(f"**{ban}**\n**Supervisors may instruct the cleanup service to delete protected records.**")
        self.assertEqual([], ConstraintGraph.from_rules(other).search_literal_compliance_paths())

        escaped = extract_rules(f"{ban}\n\\**Operators** may instruct the cleanup service to delete protected records.")
        self.assertEqual([], ConstraintGraph.from_rules(escaped).search_literal_compliance_paths())

    def test_internal_markdown_emphasis_in_compound_actor(self):
        ban = "Operators on duty must not delete protected records."
        for decorated in (
            "**Operators** on duty",
            "***Operators*** on duty",
            "`Operators` on duty",
            "Operators **on duty**",
            "__Operators__ on duty",
        ):
            with self.subTest(decorated=decorated):
                text = f"{ban}\n{decorated} may instruct the cleanup service to delete protected records."
                rules = extract_rules(text)
                self.assertEqual(["operators on duty", "operators on duty"], [r.subject for r in rules])
                self.assertEqual(text.splitlines(), [r.source.text for r in rules])
                paths = ConstraintGraph.from_rules(rules).search_literal_compliance_paths()
                self.assertEqual(["delegation_laundering"], [p.category for p in paths])

        for non_alias in (
            "**Supervisors** on duty",
            r"\**Operators** on duty",
            "Operators* on duty",
            "Operators **off duty**",
        ):
            with self.subTest(non_alias=non_alias):
                rules = extract_rules(
                    f"{ban}\n{non_alias} may instruct the cleanup service to delete protected records."
                )
                self.assertEqual([], ConstraintGraph.from_rules(rules).search_literal_compliance_paths())

        identifiers = extract_rules(
            "Operatorsfoo must not delete protected records.\n"
            "Operators_foo_ may instruct the cleanup service to delete protected records."
        )
        self.assertEqual([], ConstraintGraph.from_rules(identifiers).search_literal_compliance_paths())
        self.assertEqual("operators_foo_", identifiers[1].subject)

    def test_path_ids_are_unique_and_stable_for_independent_rule_pairs(self):
        rules = extract_rules(
            "Operators must not delete protected records.\n"
            "Operators may instruct the cleanup service to delete protected records.\n"
            "Operators must not export customer records.\n"
            "Operators may instruct the audit service to export customer records.\n"
            "Operators may export customer records."
        )
        graph = ConstraintGraph.from_rules(rules)
        expected_ids = [
            "FRC-PATH-DELEGATE-R0001-R0002",
            "FRC-PATH-DELEGATE-R0003-R0004",
            "FRC-PATH-CONFLICT-R0003-R0005",
        ]
        self.assertEqual(expected_ids, [path.path_id for path in graph.search_literal_compliance_paths()])
        self.assertEqual(expected_ids, [path.path_id for path in graph.search_literal_compliance_paths()])

    def test_direct_and_indirect_ban_closes_delegation_path(self):
        rules = extract_rules(
            "Operators must not directly or indirectly delete protected records.\n"
            "Operators may instruct the cleanup service to delete protected records."
        )
        self.assertTrue(rules[0].indirect)
        graph = ConstraintGraph.from_rules(rules)
        categories = {p.category for p in graph.search_literal_compliance_paths()}
        self.assertNotIn("delegation_laundering", categories)

    def test_graph_snapshot_preserves_source_and_paths(self):
        rules = extract_rules(
            "Operators must not delete protected records.\n"
            "Operators may instruct the cleanup service to delete protected records."
        )
        payload = ConstraintGraph.from_rules(rules).to_dict()
        self.assertIn("effect:delete:protected records", payload["nodes"])
        self.assertEqual("protected records", payload["rules"][0]["object"])
        self.assertEqual("delegation_laundering", payload["paths"][0]["category"])

    def test_scope_qualifiers_do_not_collapse_into_false_conflict(self):
        rules = extract_rules(
            "Operators must not export customer records.\n"
            "Operators may export audit records."
        )
        graph = ConstraintGraph.from_rules(rules)
        self.assertEqual([], graph.search_literal_compliance_paths())

    def test_detects_same_effect_permission_conflict(self):
        rules = extract_rules(
            "Operators must not export customer records.\n"
            "Operators may export customer records."
        )
        graph = ConstraintGraph.from_rules(rules)
        self.assertIn(
            "literal_permission_conflict",
            {p.category for p in graph.search_literal_compliance_paths()},
        )


if __name__ == "__main__":
    unittest.main()
