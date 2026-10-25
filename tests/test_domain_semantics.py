"""Domain-level contract tests for literal-compliance graph interpretations.

These tests deliberately separate supported lexical facts from semantic claims.
One unmarked regression proves a currently false HIGH-conflict inference; known
parser limitations remain expected failures so this file does not silently
promote unsupported language understanding into a passing qualification.
"""

import unittest

from freerowcochkar.constraints import ConstraintGraph, Modality
from freerowcochkar.rules import extract_rules


def graph_for(text):
    return ConstraintGraph.from_rules(extract_rules(text))


def categories_for(text):
    return [path.category for path in graph_for(text).search_literal_compliance_paths()]


class DirectAndDelegatedEffectContracts(unittest.TestCase):
    def test_unconditional_same_actor_conflict_is_a_real_candidate(self):
        self.assertEqual(
            ["literal_permission_conflict"],
            categories_for(
                "Operators must not export customer records.\n"
                "Operators may export customer records."
            ),
        )

    def test_same_actor_delegation_is_not_equivalent_to_plain_permission(self):
        self.assertEqual(
            ["delegation_laundering"],
            categories_for(
                "Operators must not export customer records.\n"
                "Operators may instruct the audit service to export customer records."
            ),
        )

    def test_different_actors_do_not_make_same_actor_conflict(self):
        self.assertEqual(
            [],
            categories_for(
                "Operators must not export customer records.\n"
                "Supervisors may export customer records."
            ),
        )

    def test_different_actor_delegation_is_not_same_actor_laundering(self):
        self.assertEqual(
            [],
            categories_for(
                "Operators must not export customer records.\n"
                "Supervisors may instruct the audit service to export customer records."
            ),
        )

    def test_direct_and_indirect_ban_does_not_infer_a_delegation_gap(self):
        self.assertNotIn(
            "delegation_laundering",
            categories_for(
                "Operators must not directly or indirectly export customer records.\n"
                "Operators may instruct the audit service to export customer records."
            ),
        )

    def test_different_effects_do_not_prove_evasion(self):
        self.assertEqual(
            [],
            categories_for(
                "Operators must not export customer records.\n"
                "Operators may export audit records."
            ),
        )

    def test_repeated_permissions_are_not_conflicting_modalities(self):
        self.assertEqual(
            [],
            categories_for(
                "Operators may export customer records.\n"
                "Operators may export customer records."
            ),
        )

    def test_requirement_and_permission_do_not_prove_a_bypass(self):
        self.assertEqual(
            [],
            categories_for(
                "Operators must export customer records.\n"
                "Operators may export customer records."
            ),
        )


class NegationAndEvidenceContracts(unittest.TestCase):
    def test_must_not_is_one_prohibition_not_a_requirement(self):
        rules = extract_rules("Operators must not export customer records.")
        self.assertEqual(1, len(rules))
        self.assertEqual(Modality.PROHIBIT, rules[0].modality)

    def test_may_not_is_a_prohibition_not_permission(self):
        rules = extract_rules("Operators may not export customer records.")
        self.assertEqual(1, len(rules))
        self.assertEqual(Modality.PROHIBIT, rules[0].modality)

    def test_never_is_a_prohibition_not_a_permission(self):
        rules = extract_rules("Operators never export customer records.")
        self.assertEqual(1, len(rules))
        self.assertEqual(Modality.PROHIBIT, rules[0].modality)

    def test_plain_factual_statements_cannot_prove_policy_bypass(self):
        self.assertEqual([], categories_for("Export logs existed yesterday.\nNo rules were agreed."))

    def test_single_ban_cannot_by_itself_prove_an_available_permission(self):
        self.assertEqual([], categories_for("Operators must not export customer records."))

    def test_path_evidence_identifies_both_exact_rule_sources(self):
        graph = graph_for(
            "Operators must not export customer records.\n"
            "Operators may export customer records."
        )
        (path,) = graph.search_literal_compliance_paths()
        self.assertEqual(("R0001", "R0002"), path.rule_ids)
        self.assertEqual((1, 2), tuple(span.line_start for span in path.spans))

    def test_subordinate_can_does_not_mint_an_authorizing_rule(self):
        # The grammatical subject is 'a claim'; 'can' is buried in a causal
        # explanation, not a policy grant.
        self.assertEqual(
            [],
            extract_rules("A claim is not executable merely because a loophole can be imagined."),
        )

    def test_descriptive_silence_is_never_approval_is_not_action_ban(self):
        # Treat descriptive denials as data until a typed action is supported.
        self.assertEqual([], extract_rules("Silence is never approval."))


class ConditionAndExceptionContracts(unittest.TestCase):
    def test_if_condition_is_preserved_in_rule_and_graph_projection(self):
        graph = graph_for("Operators may export customer records if authorization exists.")
        self.assertEqual("if authorization exists", graph.rules[0].condition)
        self.assertEqual("if authorization exists", graph.to_dict()["rules"][0]["condition"])

    def test_unless_exception_is_preserved_in_rule_and_graph_projection(self):
        graph = graph_for("Operators must not export customer records unless authorization exists.")
        self.assertEqual("unless authorization exists", graph.rules[0].exception)
        self.assertEqual("unless authorization exists", graph.to_dict()["rules"][0]["exception"])

    def test_court_order_exception_and_matching_condition_are_not_unconditional_conflict(self):
        # RED regression: exactly matching exception / condition narrows both
        # rules to the same authorized case. A HIGH unconditional graph claim is
        # unsound unless the engine proves simultaneous opposed obligations.
        text = (
            "Operators must not export patient records unless an approved court order exists.\n"
            "Operators may export patient records if an approved court order exists."
        )
        self.assertEqual(
            [],
            graph_for(text).search_literal_compliance_paths(),
            "Matching exception and condition must not create an unconditional HIGH conflict",
        )

    def test_only_if_guard_must_not_leak_into_effect_key(self):
        # The complete condition marker must be excluded from the effect.
        rules = extract_rules("Operators may export patient records only if an approved court order exists.")
        self.assertEqual(1, len(rules))
        self.assertEqual("export:patient records", rules[0].effect_key)
        self.assertEqual("only if an approved court order exists", rules[0].condition)

    def test_until_and_after_guard_are_not_unconditional_conflict(self):
        # Temporal qualifiers must be preserved rather than treated as unconditional.
        self.assertEqual(
            [],
            graph_for(
                "Operators must not export patient records until settlement.\n"
                "Operators may export patient records after settlement."
            ).search_literal_compliance_paths(),
        )

    @unittest.skip("Role-alias normalization needs explicit identity authority; string similarity is not proof")
    def test_qualified_role_alias_is_same_person_only_with_verified_identity(self):
        # Intentional TODO: aliases and principal/agent relationships cannot be
        # assumed from surface grammar alone. Requires typed identity binding.
        self.fail("Role identity resolution requires a separate source-backed contract")


if __name__ == "__main__":
    unittest.main()
