"""CLI safety: resource exhaustion must never masquerade as a clean audit."""

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from freerowcochkar.cli import main


ROOT = Path(__file__).resolve().parents[1]


def run_cli(text: str, *args: str):
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch("sys.stdin", io.StringIO(text)), redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = main(["-", *args])
    return exit_code, stdout.getvalue(), stderr.getvalue()


class CliResourceBoundTests(unittest.TestCase):
    def assert_incomplete(self, result):
        status, stdout, stderr = result
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("INCOMPLETE_UNKNOWN", stderr)
        self.assertIn("not completed", stderr)

    def test_overlarge_stdin_rejected_before_analyzer(self):
        with patch("freerowcochkar.cli.analyze") as analyzer:
            self.assert_incomplete(run_cli("x" * 131073, "--json"))
            analyzer.assert_not_called()

    def test_overlarge_file_rejected_before_analyzer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.txt"
            path.write_bytes(b"x" * 131073)
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("freerowcochkar.cli.analyze") as analyzer, redirect_stdout(stdout), redirect_stderr(stderr):
                status = main([str(path), "--json"])
            analyzer.assert_not_called()
            self.assert_incomplete((status, stdout.getvalue(), stderr.getvalue()))

    def test_many_clauses_rejected_before_analyzer(self):
        with patch("freerowcochkar.cli.analyze") as analyzer:
            self.assert_incomplete(run_cli("Operators must review logs.\n" * 65, "--json"))
            analyzer.assert_not_called()

    def test_graph_pair_amplification_rejected_before_materialization(self):
        text = "Operators must not delete records.\n" * 25 + "Operators may delete records.\n" * 25
        with patch("freerowcochkar.cli.ConstraintGraph.from_rules") as graph:
            self.assert_incomplete(run_cli(text, "--graph-json"))
            graph.assert_not_called()

    def test_single_long_line_rejected(self):
        self.assert_incomplete(run_cli("x" * 8193, "--json"))

    def test_metadata_output_amplification_rejected(self):
        self.assert_incomplete(run_cli("Operators must review logs.", "--json", "--intent", "i" * 2049))
        self.assert_incomplete(run_cli("Operators must review logs.", "--json", "--source-url", "u" * 2049))

    def test_undecodable_metadata_is_controlled_unknown_not_traceback(self):
        for option in ("--intent", "--source-url"):
            self.assert_incomplete(run_cli("Operators must review logs.", "--json", option, "\udcff"))

    def test_oversized_rendered_report_never_prints_partial_output(self):
        with patch("freerowcochkar.cli._render_text", return_value="x" * (2 * 1024 * 1024 + 1)):
            self.assert_incomplete(run_cli("Operators must review logs."))

    def test_plain_text_escapes_untrusted_terminal_sequences(self):
        status, stdout, stderr = run_cli(
            "Operators must not delete \x1b[31mrecords\x1b[0m.\n",
            "--intent", "No \x1b[1mterminal markup",
        )
        self.assertIn(status, (0, 1))
        self.assertEqual("", stderr)
        self.assertNotIn("\x1b", stdout)
        self.assertIn("\\x1b", stdout)

    def test_invalid_utf8_stdin_controlled_nonzero(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        for options in (("--json",), ("--provenance", "--json"), ("--graph-json",)):
            completed = subprocess.run(
                [sys.executable, "-m", "freerowcochkar.cli", "-", *options],
                input=b"\xff", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=ROOT, env=env, check=False, timeout=3,
            )
            self.assertEqual(2, completed.returncode)
            self.assertEqual(b"", completed.stdout)
            self.assertIn(b"INCOMPLETE_UNKNOWN", completed.stderr)
            self.assertNotIn(b"Traceback", completed.stderr)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO test")
    def test_named_pipe_never_blocks_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pipe"
            os.mkfifo(path)
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
            completed = subprocess.run(
                [sys.executable, "-m", "freerowcochkar.cli", str(path), "--json"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=ROOT, env=env, check=False, timeout=2,
            )
            self.assertEqual(2, completed.returncode)
            self.assertEqual(b"", completed.stdout)
            self.assertIn(b"INCOMPLETE_UNKNOWN", completed.stderr)

    def test_bounded_normal_report_and_graph_preserve_contracts(self):
        for flag in ("--json", "--graph-json"):
            result = run_cli("Operators may export audit logs.\n", flag)
            self.assertEqual(0, result[0])
            self.assertIn('"coverage"', result[1])
            self.assertEqual("", result[2])
        conflict = "Operators must not delete records.\nOperators may delete records.\n"
        self.assertEqual(1, run_cli(conflict, "--graph-json")[0])


if __name__ == "__main__":
    unittest.main()
