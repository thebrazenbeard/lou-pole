"""Source identity and honest parser-coverage regression contract.

Proposed opt-in API: analyze(text, include_source=True, source_url=None),
CLI --provenance [--source-url URL]. The digest covers the exact UTF-8 encoded
*analyzed string*, not claimed remote bytes or verified source authenticity.
Without opt-in, serialized report/graph shape remains backwards compatible.
"""

import hashlib
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from freerowcochkar import analyze
from freerowcochkar.cli import main


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_cli(text, *args):
    output = io.StringIO()
    with patch("sys.stdin", io.StringIO(text)), redirect_stdout(output):
        status = main(["-", *args])
    return status, json.loads(output.getvalue())


class SourceProvenanceContracts(unittest.TestCase):
    def test_default_report_serialization_does_not_acquire_source_field(self):
        payload = analyze("Operators may export audit logs.").to_dict()
        self.assertNotIn("source", payload)

    def test_explicit_source_opt_in_binds_exact_analyzed_content_digest(self):
        text = "Operators may export caf\u00e9 records.\n"
        source = analyze(text, include_source=True).to_dict()["source"]
        self.assertEqual(digest(text), source["content_sha256"])
        self.assertEqual("analyzed_text_utf8", source["digest_basis"])

    def test_url_is_only_declared_and_not_attested_or_fetched(self):
        url = "https://example.invalid/not-fetched.txt"
        source = analyze("Operators may export audit logs.", include_source=True, source_url=url).to_dict()["source"]
        self.assertEqual(url, source["declared_url"])
        self.assertEqual("not_checked", source["verification"])

    def test_same_url_changed_content_requires_different_content_digest(self):
        url = "https://example.invalid/policy"
        left = analyze("Operators may export logs.\n", include_source=True, source_url=url).to_dict()["source"]
        right = analyze("Operators may not export logs.\n", include_source=True, source_url=url).to_dict()["source"]
        self.assertNotEqual(left["content_sha256"], right["content_sha256"])
        self.assertEqual(left["declared_url"], right["declared_url"])

    def test_identical_content_with_different_url_labels_retains_same_digest(self):
        text = "Operators must not merge main."
        left = analyze(text, include_source=True, source_url="https://example.invalid/a").to_dict()["source"]
        right = analyze(text, include_source=True, source_url="https://example.invalid/b").to_dict()["source"]
        self.assertEqual(left["content_sha256"], right["content_sha256"])
        self.assertNotEqual(left["declared_url"], right["declared_url"])
        self.assertEqual("not_checked", right["verification"])

    def test_digest_binds_line_endings_of_analyzed_string_not_displayed_lines(self):
        left = "Operators may export audit logs.\r\n"
        right = "Operators may export audit logs.\n"
        source_left = analyze(left, include_source=True).to_dict()["source"]
        source_right = analyze(right, include_source=True).to_dict()["source"]
        self.assertEqual(digest(left), source_left["content_sha256"])
        self.assertNotEqual(source_left["content_sha256"], source_right["content_sha256"])

    def test_cli_report_and_graph_bind_same_string_in_same_digest_scheme(self):
        text = "Operators may export audit logs.\n"
        _, report = run_cli(text, "--json", "--provenance", "--source-url", "https://example.invalid/rules")
        _, graph = run_cli(text, "--graph-json", "--provenance", "--source-url", "https://example.invalid/rules")
        self.assertEqual(digest(text), report["source"]["content_sha256"])
        self.assertEqual(report["source"], graph["source"])

    def test_cli_without_opt_in_preserves_legacy_graph_shape(self):
        _, graph = run_cli("Operators may export audit logs.", "--graph-json")
        self.assertNotIn("source", graph)


class CoverageStatusContracts(unittest.TestCase):
    def test_empty_document_is_identified_as_empty_not_clear(self):
        payload = analyze("\n \t ").to_dict()
        self.assertEqual("empty_input", payload["coverage"]["status"])
        self.assertEqual(0, payload["coverage"]["nonempty_clause_count"])
        self.assertEqual(0, payload["finding_count"])

    def test_nonempty_nonnormative_input_is_no_rules_not_full_coverage(self):
        payload = analyze("A transfer happened yesterday.").to_dict()
        self.assertEqual("no_rules_extracted", payload["coverage"]["status"])
        self.assertEqual(1, payload["coverage"]["nonempty_clause_count"])
        self.assertEqual(0, payload["coverage"]["unparsed_normative_clause_count"])

    def test_unsupported_future_obligation_does_not_look_fully_covered(self):
        payload = analyze("The reviewer will approve payments tomorrow.").to_dict()
        self.assertEqual("no_rules_extracted", payload["coverage"]["status"])
        self.assertEqual(0, payload["coverage"]["extracted_rule_count"])
        self.assertEqual(0, payload["risk_score"])

    def test_partial_heuristic_coverage_is_never_called_complete(self):
        payload = analyze(
            "Operators must not export customer records.\n"
            "Only authorized operators export audit logs."
        ).to_dict()
        coverage = payload["coverage"]
        self.assertEqual("heuristic_partial", coverage["status"])
        self.assertGreaterEqual(coverage["unparsed_normative_clause_count"], 1)
        self.assertNotIn("complete", coverage["status"])

    def test_extracted_rules_without_parse_gaps_are_still_not_certified(self):
        coverage = analyze("Operators must not export customer records.").to_dict()["coverage"]
        self.assertEqual("heuristic_extracted_unverified", coverage["status"])
        self.assertNotIn("complete", coverage["status"])
        self.assertNotIn("safe", coverage["status"])


if __name__ == "__main__":
    unittest.main()
