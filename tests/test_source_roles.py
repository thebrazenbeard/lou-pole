"""Black-box contracts for conservative Markdown source-role masking."""

import unittest

from freerowcochkar.constraints import Modality
from freerowcochkar.rules import extract_rules


def mask(text: str, *, include_nonoperative: bool = False):
    try:
        from freerowcochkar.source_roles import mask_nonoperative_markdown
    except ModuleNotFoundError as exc:
        raise AssertionError("Markdown source-role masking is not implemented") from exc
    return mask_nonoperative_markdown(text, include_nonoperative=include_nonoperative)


class SourceRoleTests(unittest.TestCase):
    def test_active_ban_survives_while_quoted_permission_is_masked(self):
        text = "- Operators must not export records.\n> Operators may export records.\n"
        result = mask(text)

        self.assertEqual(
            "- Operators must not export records.\n" + " " * 31 + "\n",
            result.masked_text,
        )
        self.assertEqual(
            [(2, 2, "quoted")],
            [(s.line_start, s.line_end, s.reason) for s in result.excluded_spans],
        )

    def test_multiline_backtick_fence_masks_example_with_crlf_unchanged(self):
        text = (
            "- Operators must not export records.\r\n"
            "```python\r\n"
            "Operators may export records.\r\n"
            "# Example heading\r\n"
            "```\r\n"
            "- Operators must not deploy without approval.\r\n"
        )
        result = mask(text)

        expected_lines = text.splitlines(keepends=True)
        for n in range(1, 5):
            expected_lines[n] = " " * (len(expected_lines[n]) - 2) + "\r\n"
        self.assertEqual("".join(expected_lines), result.masked_text)
        self.assertEqual(len(text), len(result.masked_text))
        self.assertEqual(
            [(2, 5, "fenced")],
            [(s.line_start, s.line_end, s.reason) for s in result.excluded_spans],
        )

    def test_markdown_headings_can_contain_operative_prohibitions(self):
        text = (
            "# Operators must not export records.\n"
            "### Exceptions and examples\n"
            "- Operators may export records.\n"
            "#hashtag content must remain active text.\n"
        )
        result = mask(text)
        self.assertEqual(text, result.masked_text)
        self.assertEqual((), result.excluded_spans)
        # Both heading prohibition and list permission survive source masking.
        self.assertEqual(3, len(extract_rules(result.masked_text)))

    def test_tilde_fence_closes_only_with_matching_sufficient_delimiter(self):
        text = (
            "- Operators must not deploy.\n"
            "~~~~ example\n"
            "> Operators may deploy.\n"
            "```\n"
            "~~~\n"
            "~~~~~\n"
            "- Operators must not export.\n"
        )
        result = mask(text)

        self.assertEqual(
            "- Operators must not deploy.\n"
            + "".join(" " * len(line) + "\n" for line in text.splitlines()[1:6])
            + "- Operators must not export.\n",
            result.masked_text,
        )
        self.assertEqual(
            [(2, 6, "fenced")],
            [(s.line_start, s.line_end, s.reason) for s in result.excluded_spans],
        )

    def test_fence_opened_inside_a_list_item_masks_its_example(self):
        text = (
            "- Operators must not export records.\n"
            "- ```policy\n"
            "  Operators may export records.\n"
            "  ```\n"
            "- Operators must not deploy records.\n"
        )
        result = mask(text)
        lines = text.splitlines(keepends=True)
        expected = (
            lines[0]
            + "".join(" " * (len(line) - 1) + "\n" for line in lines[1:4])
            + lines[4]
        )
        self.assertEqual(expected, result.masked_text)
        self.assertEqual(
            [(2, 4, "fenced")],
            [(s.line_start, s.line_end, s.reason) for s in result.excluded_spans],
        )

    def test_explicit_include_nonoperative_override_keeps_literal_source(self):
        text = "# Example\n> Operators may export.\n~~~\nOperators may delete.\n~~~\n"
        result = mask(text, include_nonoperative=True)
        self.assertEqual(text, result.masked_text)
        self.assertEqual((), result.excluded_spans)

    def test_quote_and_fence_examples_do_not_become_parsed_permissions(self):
        text = (
            "- Operators must not export records.\n"
            "> Operators may export records.\n"
            "~~~example\n"
            "Operators may export records.\n"
            "~~~\n"
        )
        rules = extract_rules(mask(text).masked_text)
        self.assertEqual(1, len(rules))
        self.assertEqual(Modality.PROHIBIT, rules[0].modality)
        self.assertEqual("operators", rules[0].subject)
        self.assertEqual("export:records", rules[0].effect_key)

    def test_nested_list_quote_is_nonoperative_but_neighbor_bullet_is_active(self):
        text = (
            "- Operators must not export records.\n"
            "- > Operators may export records.\n"
            "- Operators must not deploy records.\n"
        )
        result = mask(text)
        self.assertEqual(
            "- Operators must not export records.\n"
            + " " * len("- > Operators may export records.") + "\n"
            + "- Operators must not deploy records.\n",
            result.masked_text,
        )
        self.assertEqual(
            [(2, 2, "quoted")],
            [(s.line_start, s.line_end, s.reason) for s in result.excluded_spans],
        )

    def test_invalid_backtick_info_does_not_hide_following_active_policy(self):
        text = "```invalid`info\n- Operators must not export records.\n"
        result = mask(text)
        self.assertEqual(text, result.masked_text)
        self.assertEqual((), result.excluded_spans)


if __name__ == "__main__":
    unittest.main()
