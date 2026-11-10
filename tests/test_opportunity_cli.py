import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from freerowcochkar.opportunities_cli import main


class OpportunityCliTests(unittest.TestCase):
    def run_cli(self, payload: bytes):
        output = io.StringIO()
        errors = io.StringIO()
        with patch("sys.stdin", io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")):
            with redirect_stdout(output), redirect_stderr(errors):
                exit_code = main(["-"])
        return exit_code, output.getvalue(), errors.getvalue()

    def test_json_route_is_advisory_never_executed(self):
        payload = json.dumps({
            "goal": "preview",
            "initial_capabilities": ["source"],
            "allowed_effects": ["local_workspace"],
            "cost_ceiling": 0,
            "actions": [{"id": "render", "requires": ["source"], "provides": ["preview"],
                         "effects": ["local_workspace"], "provenance": "source/audit@123"}],
        }).encode()
        code, output, errors = self.run_cli(payload)
        self.assertEqual(code, 0, errors)
        report = json.loads(output)
        self.assertEqual(report["status"], "AVAILABLE")
        self.assertEqual(report["action_ids"], ["render"])
        self.assertFalse(report["executed"])
        self.assertFalse(report["verified"])
        self.assertEqual(report["evidence_class"], "CALLER_SUPPLIED_UNVERIFIED")

    def test_invalid_utf8_rejected_without_partial_stdout(self):
        code, output, errors = self.run_cli(b"\xff")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("INCOMPLETE_UNKNOWN", errors)

    def test_oversized_input_rejected(self):
        code, output, errors = self.run_cli(b" " * (128 * 1024 + 1))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("INCOMPLETE_UNKNOWN", errors)

    def test_unknown_json_fields_rejected(self):
        code, output, errors = self.run_cli(b'{"goal":"x","unknown":"not approved"}')
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertNotIn("not approved", errors)

    def test_duplicate_keys_not_allowed(self):
        code, output, errors = self.run_cli(b'{"goal":"x","goal":"y"}')
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("INCOMPLETE_UNKNOWN", errors)


if __name__ == "__main__":
    unittest.main()
