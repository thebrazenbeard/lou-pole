import unittest

from freerowcochkar.constraints import Modality
from freerowcochkar.rules import extract_rules


class NegatedModalTests(unittest.TestCase):
    def test_common_negated_modals_are_prohibitions_with_same_effect(self):
        cases = (
            "Operators must never export customer records.",
            "Operators shall never export customer records.",
            "Operators may never export customer records.",
            "Operators can not export customer records.",
            "Operators cannot export customer records.",
            "Operators can't export customer records.",
            "Operators can’t export customer records.",
            "Operators are not allowed to export customer records.",
            "Operators are not permitted to export customer records.",
            "Operators are never allowed to export customer records.",
            "Operators are never permitted to export customer records.",
            "Operators should never export customer records.",
        )
        for source in cases:
            with self.subTest(source=source):
                rules = extract_rules(source)
                self.assertEqual(1, len(rules))
                self.assertEqual(Modality.PROHIBIT, rules[0].modality)
                self.assertEqual("operators", rules[0].subject)
                self.assertEqual("export:customer records", rules[0].effect_key)

    def test_no_subject_modal_prohibits_without_misnaming_actor(self):
        for source in (
            "No operator may export customer records.",
            "No operator can export customer records.",
        ):
            with self.subTest(source=source):
                rules = extract_rules(source)
                self.assertEqual(1, len(rules))
                self.assertEqual(Modality.PROHIBIT, rules[0].modality)
                self.assertEqual("operator", rules[0].subject)
                self.assertEqual("export:customer records", rules[0].effect_key)

    def test_unsupported_embedded_negation_does_not_become_permission(self):
        rules = extract_rules("Operators may by no means export customer records.")
        self.assertTrue(all(rule.modality != Modality.PERMIT for rule in rules))

    def test_quantified_and_double_negations_are_not_misclassified(self):
        cases = (
            "No operator must export customer records.",
            "No operator shall export customer records.",
            "Nobody may transfer funds.",
            "No one may transfer funds.",
            "No-one may transfer funds.",
            "None of the operators may export customer records.",
            "Neither operator may export customer records.",
            "Not a single operator may export customer records.",
            "No operator may not export customer records.",
            "Operators cannot not export customer records.",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual([], extract_rules(source))

    def test_not_only_but_also_does_not_become_prohibition(self):
        cases = (
            "Operators may not only export audit records, but also read them.",
            "Operators can not only export audit records, but also read them.",
            "Operators must not only export audit records, but also read them.",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual([], extract_rules(source))

    def test_subordinate_negation_is_not_standalone_prohibition(self):
        cases = (
            "We do allow automated reports so long as they do not produce excessive amounts of traffic.",
            "A claim is not executable merely because a semantic loophole can be imagined.",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual([], extract_rules(source))

    def test_absence_of_obligation_is_not_a_prohibition(self):
        cases = (
            "Operators do not have to export customer records.",
            "Operators do not need to export customer records.",
            "Operators are not required to export customer records.",
            "Operators never have to export customer records.",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual([], extract_rules(source))

    def test_existing_affirmative_modals_still_parse(self):
        cases = (
            ("Operators may export audit records.", Modality.PERMIT),
            ("Operators can export audit records.", Modality.PERMIT),
            ("Operators are allowed to export audit records.", Modality.PERMIT),
            ("Operators must export audit records.", Modality.REQUIRE),
            ("Operators must not export audit records.", Modality.PROHIBIT),
        )
        for source, modality in cases:
            with self.subTest(source=source):
                rules = extract_rules(source)
                self.assertEqual(1, len(rules))
                self.assertEqual(modality, rules[0].modality)
                self.assertEqual("export:audit records", rules[0].effect_key)


if __name__ == "__main__":
    unittest.main()
