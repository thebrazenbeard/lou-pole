import unittest

from freerowcochkar import analyze
from freerowcochkar.constraints import ConstraintGraph
from freerowcochkar.rules import extract_rules


class PrecedenceGuardrailTests(unittest.TestCase):
    def test_distinct_record_classes_are_not_a_high_conflict(self):
        report = analyze(
            "Operators must not export customer records.\n"
            "Operators may export audit records."
        )
        self.assertNotIn("precedence_collision", {f.category for f in report.findings})
        self.assertNotIn("literal_permission_conflict", {f.category for f in report.findings})

    def test_distinct_actors_are_not_a_high_conflict(self):
        report = analyze(
            "Operators must not export customer records.\n"
            "Supervisors may export customer records."
        )
        self.assertNotIn("precedence_collision", {f.category for f in report.findings})
        self.assertNotIn("literal_permission_conflict", {f.category for f in report.findings})

    def test_matching_exception_and_condition_are_consistent(self):
        text = (
            "Operators must not delete protected records unless an approved court order exists.\n"
            "Operators may delete protected records when an approved court order exists."
        )
        graph = ConstraintGraph.from_rules(extract_rules(text))
        self.assertEqual([], graph.search_literal_compliance_paths())
        report = analyze(text)
        self.assertNotIn("precedence_collision", {f.category for f in report.findings})
        self.assertNotIn("literal_permission_conflict", {f.category for f in report.findings})

    def test_unqualified_same_actor_same_effect_remains_conflict(self):
        report = analyze(
            "Operators must not delete protected records.\n"
            "Operators may delete protected records."
        )
        self.assertIn("literal_permission_conflict", {f.category for f in report.findings})

    def test_distinct_guards_do_not_prove_unconditional_conflict(self):
        text = (
            "Operators must not delete protected records when the account is inactive.\n"
            "Operators may delete protected records when the account is active."
        )
        self.assertEqual([], ConstraintGraph.from_rules(extract_rules(text)).search_literal_compliance_paths())
        findings = analyze(text).findings
        self.assertNotIn("precedence_collision", {f.category for f in findings})
        self.assertNotIn("literal_permission_conflict", {f.category for f in findings})
        self.assertIn("guard_overlap_unknown", {f.category for f in findings})

    def test_cannot_prohibition_with_purpose_limited_permission_is_inspected(self):
        report = analyze(
            "Operators cannot export customer records.\n"
            "Operators may export customer records for support."
        )
        self.assertIn("precedence_collision", {f.category for f in report.findings})

    def test_support_limited_permission_remains_a_candidate(self):
        report = analyze(
            "Operators must not export customer records.\n"
            "Operators may export customer records for support."
        )
        self.assertIn("precedence_collision", {f.category for f in report.findings})


if __name__ == "__main__":
    unittest.main()
