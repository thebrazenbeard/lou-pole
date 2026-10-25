"""An intent annotation must never masquerade as a proven temporal invariant."""

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from freerowcochkar import analyze
from freerowcochkar.cli import main


ABA_SOURCE = """\
def record_satisfaction(target, amount):
    if current_goal.target == target and amount >= 0.7:
        current_goal = None
"""
ABA_INTENT = (
    "A delayed satisfaction claim for goal-0001 must not complete "
    "newer goal-0002 with the same target."
)


def graph_report(text, *args):
    out = io.StringIO()
    with patch("sys.stdin", io.StringIO(text)), redirect_stdout(out):
        code = main(["-", "--graph-json", *args])
    return code, json.loads(out.getvalue())


class IntentEvaluationContracts(unittest.TestCase):
    def test_report_explicitly_labels_unchecked_temporal_goal_intent(self):
        payload = analyze(ABA_SOURCE, profile="code", intent=ABA_INTENT).to_dict()
        self.assertEqual(ABA_INTENT, payload["intent"])
        scope = payload["coverage"]["intent_evaluation"]
        self.assertEqual("not_evaluated", scope["status"])
        self.assertIn("cross_instance_identity_and_credit", scope["unsupported_mechanisms"])
        self.assertIn("ordered_state_transitions", scope["unsupported_mechanisms"])
        self.assertIn("not", scope["notice"].lower())

    def test_graph_json_retains_declared_intent_with_same_non_enforcement_status(self):
        _, graph = graph_report(ABA_SOURCE, "--intent", ABA_INTENT)
        report = analyze(ABA_SOURCE, profile="code", intent=ABA_INTENT).to_dict()
        self.assertEqual(ABA_INTENT, graph["intent"])
        self.assertEqual(report["coverage"]["intent_evaluation"],
                         graph["coverage"]["intent_evaluation"])

    def test_without_intent_legacy_shape_is_unchanged(self):
        payload = analyze(ABA_SOURCE).to_dict()
        self.assertNotIn("intent_evaluation", payload["coverage"])
        _, graph = graph_report(ABA_SOURCE)
        self.assertNotIn("intent_evaluation", graph["coverage"])
        self.assertNotIn("intent", graph)

    def test_human_report_cannot_suggest_intent_was_checked(self):
        stdout = io.StringIO()
        with patch("sys.stdin", io.StringIO(ABA_SOURCE)), redirect_stdout(stdout):
            main(["-", "--profile", "code", "--intent", ABA_INTENT])
        self.assertIn("not evaluated", stdout.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
