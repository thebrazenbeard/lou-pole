"""Security regression: workspace-open must not execute repository code."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def contains_folder_open(node):
    if isinstance(node, dict):
        if node.get("runOn") == "folderOpen":
            return True
        return any(contains_folder_open(value) for value in node.values())
    if isinstance(node, list):
        return any(contains_folder_open(value) for value in node)
    return False


class EditorStartupSecurity(unittest.TestCase):
    def test_no_folder_open_tasks_in_platform_overrides(self):
        path = ROOT / ".vscode" / "tasks.json"
        if path.exists():
            document = json.loads(path.read_text(encoding="utf-8-sig"))
            self.assertFalse(contains_folder_open(document),
                             "workspace task must not run automatically on folder open")

    def test_workspace_settings_do_not_enable_automatic_tasks(self):
        path = ROOT / ".vscode" / "settings.json"
        if path.exists():
            document = json.loads(path.read_text(encoding="utf-8-sig"))
            self.assertIsNot(document.get("task.allowAutomaticTasks"), True,
                             "workspace must not enable automatic tasks")
            self.assertFalse(contains_folder_open(document),
                             "workspace settings must not contain auto-open tasks")

    def test_font_path_cannot_host_non_font_code(self):
        path = ROOT / "public" / "fonts" / "fa-solid-600.ttf"
        if path.exists():
            self.assertIn(path.read_bytes()[:4],
                          (b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf"),
                          "font extension contains content without a font signature")


if __name__ == "__main__":
    unittest.main()
