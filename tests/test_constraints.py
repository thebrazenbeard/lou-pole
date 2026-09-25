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
