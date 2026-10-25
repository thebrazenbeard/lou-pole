import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from freerowcochkar import analyze
from freerowcochkar.cli import main


class ParseCoverageTests(unittest.TestCase):
    def test_unparsed_only_imperative_is_visible(self):
        result = analyze("Only test systems you are authorized to test.").to_dict()
        self.assertEqual(1, result["coverage"]["unparsed_normative_clause_count"])

    def test_unparsed_normative_clause_is_explicit_in_json(self):
        report = analyze("Operators are forbidden to view protected records.")
        result = report.to_dict()
        self.assertEqual(0, result["finding_count"])
        self.assertEqual(0, result["coverage"]["extracted_rule_count"])
        self.assertEqual(1, result["coverage"]["unparsed_normative_clause_count"])
        self.assertIn("not a safety determination", result["coverage"]["notice"])

    def test_graph_json_reports_unparsed_normative_clause(self):
        stdin = io.StringIO("Operators are forbidden to view protected records.")
        stdout = io.StringIO()
        with patch("sys.stdin", stdin), redirect_stdout(stdout):
            exit_code = main(["--graph-json", "-"])
        result = json.loads(stdout.getvalue())
        self.assertEqual(0, exit_code)  # No graph path; coverage is separate.
        self.assertEqual(1, result["coverage"]["unparsed_normative_clause_count"])
        self.assertEqual("Operators are forbidden to view protected records.",
                         result["coverage"]["unparsed_normative_clauses"][0]["text"])


if __name__ == "__main__":
    unittest.main()
