"""Prevent examples and quoted material from posing as operative policy.

Markdown block quotes and fenced examples are *not proved operative* merely
because their text parses as normative grammar. These fixtures require either
explicit operative-context selection or bounded unknown/excluded coverage; no
automatic HIGH finding may arise from mixing such snippets with active rules.

This is intentionally not a general Markdown parser or a ruling that every
blockquote is nonbinding: an author may explicitly designate a quoted policy
as operative. That attribution needs separate evidence, not punctuation loss.
"""

import unittest
import io
import json
from contextlib import redirect_stdout
from unittest.mock import patch

from freerowcochkar import analyze
from freerowcochkar.constraints import ConstraintGraph
from freerowcochkar.models import Severity
from freerowcochkar.rules import extract_rules
from freerowcochkar.cli import main


def high_categories(text):
    return {
        finding.category
        for finding in analyze(text, profile="instructions").findings
        if finding.severity == Severity.HIGH
    }


class MarkdownSourceRoleContracts(unittest.TestCase):
    def test_quoted_permission_must_not_override_active_prohibition(self):
        text = (
            "Operators must not export customer records.\n"
            "> Operators may export customer records.\n"
        )
        self.assertNotIn("precedence_collision", high_categories(text))
        self.assertNotIn("literal_permission_conflict", high_categories(text))

    def test_quoted_prohibition_must_not_override_active_permission(self):
        text = (
            "> Operators must not export customer records.\n"
            "Operators may export customer records.\n"
        )
        self.assertNotIn("precedence_collision", high_categories(text))
        self.assertNotIn("literal_permission_conflict", high_categories(text))

    def test_fenced_example_permission_must_not_override_active_prohibition(self):
        text = (
            "Operators must not export customer records.\n"
            "```text\n"
            "Operators may export customer records.\n"
            "```\n"
        )
        self.assertNotIn("precedence_collision", high_categories(text))
        self.assertNotIn("literal_permission_conflict", high_categories(text))

    def test_nested_block_quote_does_not_make_an_active_permission(self):
        text = (
            "Operators must not export customer records.\n"
            "> > Operators may export customer records.\n"
        )
        graph = ConstraintGraph.from_rules(extract_rules(text))
        self.assertEqual([], graph.search_literal_compliance_paths())

    def test_fenced_and_quoted_only_document_has_no_operative_rule(self):
        text = (
            "> Operators may export customer records.\n"
            "```text\n"
            "Operators must not export customer records.\n"
            "```\n"
        )
        coverage = analyze(text).to_dict()["coverage"]
        self.assertEqual(0, coverage["extracted_rule_count"])
        self.assertEqual("no_rules_extracted", coverage["status"])
        self.assertGreaterEqual(coverage["nonoperative_clause_count"], 2)

    def test_quoted_source_is_preserved_in_coverage_not_recast_as_plain_text(self):
        text = "> Operators may export customer records.\n"
        excluded = analyze(text).to_dict()["coverage"]["nonoperative_clauses"]
        self.assertTrue(any(
            item["text"].startswith("> ") and item["source_role"] == "quoted"
            for item in excluded
        ))

    def test_fenced_source_is_classified_as_example_context(self):
        text = "```policy-example\nOperators may export customer records.\n```\n"
        excluded = analyze(text).to_dict()["coverage"]["nonoperative_clauses"]
        self.assertTrue(any(item["source_role"] == "fenced" for item in excluded))

    def test_bulleted_rules_remain_operative_policy(self):
        text = (
            "- Operators must not export customer records.\n"
            "- Operators may export customer records.\n"
        )
        self.assertIn("literal_permission_conflict", high_categories(text))

    def test_plain_unquoted_same_actor_conflict_still_reports_high(self):
        text = (
            "Operators must not export customer records.\n"
            "Operators may export customer records.\n"
        )
        self.assertIn("literal_permission_conflict", high_categories(text))

    def test_operative_markdown_heading_prohibition_cannot_disappear(self):
        text = (
            "# Operators must not export customer records.\n"
            "Operators may export customer records.\n"
        )
        self.assertIn("literal_permission_conflict", high_categories(text))
        self.assertEqual(2, analyze(text).coverage["extracted_rule_count"])

    def test_explicit_quote_override_audits_cross_context_conflict(self):
        text = (
            "Operators must not export customer records.\n"
            "> Operators may export customer records.\n"
        )
        self.assertNotIn("literal_permission_conflict", high_categories(text))
        full = analyze(text, profile="instructions", include_nonoperative=True)
        self.assertIn(
            "literal_permission_conflict", {f.category for f in full.findings}
        )

    def test_cli_graph_and_report_agree_on_source_role_override(self):
        text = (
            "Operators must not export customer records.\n"
            "> Operators may export customer records.\n"
        )
        for output_mode in ("--graph-json", "--json"):
            for override, expected_count in ((False, 1), (True, 2)):
                output = io.StringIO()
                argv = ["-", output_mode]
                if override:
                    argv.append("--include-nonoperative")
                with patch("sys.stdin", io.StringIO(text)), redirect_stdout(output):
                    main(argv)
                payload = json.loads(output.getvalue())
                self.assertEqual(expected_count, payload["coverage"]["extracted_rule_count"])
                self.assertEqual(0 if override else 1,
                                 payload["coverage"]["nonoperative_clause_count"])

    @unittest.skip("Unmarked 'Example:' sections need explicit source-role authority; heading inference is not enough")
    def test_unquoted_example_section_is_only_nonoperative_with_verified_marking(self):
        self.fail("Caller must supply operative/example span roles for ambiguous prose sections")


if __name__ == "__main__":
    unittest.main()
