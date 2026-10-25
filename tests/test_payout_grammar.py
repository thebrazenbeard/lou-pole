import unittest

from freerowcochkar.analyzer import analyze
from freerowcochkar.constraints import ConstraintGraph, Modality
from freerowcochkar.rules import extract_rules


class PayoutGrammarTests(unittest.TestCase):
    def test_without_approval_is_a_guard_not_part_of_payment_effect(self):
        source = (
            "Operators must not send payouts without approval.\n"
            "Operators may send payouts."
        )
        rules = extract_rules(source)
        self.assertEqual(2, len(rules))
        self.assertEqual(Modality.PROHIBIT, rules[0].modality)
        self.assertEqual("send:payouts", rules[0].effect_key)
        self.assertEqual("without approval", rules[0].condition)
        self.assertEqual("send:payouts", rules[1].effect_key)
        self.assertIn(
            "literal_permission_conflict",
            {path.category for path in ConstraintGraph.from_rules(rules).search_literal_compliance_paths()},
        )

    def test_passive_payout_clause_remains_unresolved_without_actor_inference(self):
        source = (
            "Payouts must not be sent without explicit approval.\n"
            "Agents may send payouts."
        )
        rules = extract_rules(source)
        self.assertEqual(1, len(rules))
        self.assertEqual("agents", rules[0].subject)
        self.assertEqual(Modality.PERMIT, rules[0].modality)
        self.assertEqual([], ConstraintGraph.from_rules(rules).search_literal_compliance_paths())
        report = analyze(source, profile="instructions")
        self.assertEqual(1, report.coverage["unparsed_normative_clause_count"])

    def test_have_service_delegation_is_unresolved_not_fake_permission(self):
        source = (
            "Operators must not delete protected records.\n"
            "Operators may have cleanup service delete protected records."
        )
        rules = extract_rules(source)
        self.assertEqual(1, len(rules))
        self.assertEqual(Modality.PROHIBIT, rules[0].modality)
        self.assertEqual([], ConstraintGraph.from_rules(rules).search_literal_compliance_paths())
        report = analyze(source, profile="instructions")
        self.assertEqual(1, report.coverage["unparsed_normative_clause_count"])

    def test_prohibited_causative_have_is_also_unresolved(self):
        source = "Operators must not have cleanup service delete protected records."
        self.assertEqual([], extract_rules(source))
        report = analyze(source, profile="instructions")
        self.assertEqual(1, report.coverage["unparsed_normative_clause_count"])

    def test_existing_simple_conditional_and_affirmative_rules_preserved(self):
        rules = extract_rules(
            "Operators must not send payouts.\n"
            "Operators may send payouts when approval is recorded."
        )
        self.assertEqual(2, len(rules))
        self.assertEqual("send:payouts", rules[0].effect_key)
        self.assertEqual("send:payouts", rules[1].effect_key)
        self.assertEqual("when approval is recorded", rules[1].condition)

    def test_unrelated_without_word_is_not_assumed_to_be_approval_guard(self):
        rules = extract_rules("Operators may ship Without Limits merchandise.")
        self.assertEqual(1, len(rules))
        self.assertEqual("ship:without limits merchandise", rules[0].effect_key)
        self.assertIsNone(rules[0].condition)

    def test_approval_guard_without_terminal_punctuation(self):
        rules = extract_rules("Operators must not send payouts without approval")
        self.assertEqual(1, len(rules))
        self.assertEqual("send:payouts", rules[0].effect_key)
        self.assertEqual("without approval", rules[0].condition)


if __name__ == "__main__":
    unittest.main()
