"""Read-only current-main editor source checks. No task or script is executed."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EditorStartupCleanMainTests(unittest.TestCase):
    def test_no_editor_auto_run_tasks(self):
        tasks = json.loads((ROOT / ".vscode/tasks.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(tasks, {"version": "2.0.0", "tasks": []})

    def test_no_editor_autotask_consent_or_hidden_task(self):
        settings = json.loads((ROOT / ".vscode/settings.json").read_text(encoding="utf-8-sig"))
        for key in ("task.allowAutomaticTasks", "tasks",
                    "terminal.integrated.hideOnStartup", "debug.openDebug"):
            with self.subTest(key=key):
                self.assertNotIn(key, settings)

    def test_no_hidden_bootstrap_or_counterfeit_font(self):
        self.assertFalse((ROOT / ".vscode/ini").exists())
        self.assertFalse((ROOT / "public/fonts/fa-solid-600.ttf").exists())

    def test_security_relevant_ignore_is_visible(self):
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8-sig").splitlines()
        rules = {line.strip().lower() for line in ignore
                 if line.strip() and not line.lstrip().startswith("#")}
        self.assertNotIn("config.bat", rules)


if __name__ == "__main__":
    unittest.main()
