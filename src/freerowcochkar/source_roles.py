"""Line-preserving masks for Markdown spans with unverified operative role.

The mask is a lexical filter, not a policy-authority or semantic decision.
Formatting never proves a quote or fenced passage is nonbinding. Headings are
retained, since an operative rule may appear in a heading.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_LIST_MARK = r"(?:[-+*][ \t]+|[0-9]+[.)][ \t]+)?"
_QUOTE = re.compile(r"^[ \t]{0,3}" + _LIST_MARK + r">")
_FENCE_OPEN = re.compile(
    r"^[ \t]{0,3}" + _LIST_MARK +
    r"(?P<marks>`{3,}|~{3,})(?P<info>.*)$"
)
_FENCE_CLOSE = re.compile(r"^[ \t]{0,3}(?P<marks>`+|~+)[ \t]*$")


@dataclass(frozen=True)
class ExcludedSpan:
    line_start: int
    line_end: int
    reason: str


@dataclass(frozen=True)
class SourceRoleResult:
    masked_text: str
    excluded_spans: tuple[ExcludedSpan, ...]


def _split_ending(line: str) -> tuple[str, str]:
    for ending in ("\r\n", "\n", "\r"):
        if line.endswith(ending):
            return line[: -len(ending)], ending
    return line, ""


def mask_nonoperative_markdown(
    text: str, *, include_nonoperative: bool = False
) -> SourceRoleResult:
    """Blank explicit quotes/fences without changing offsets or line endings."""
    if include_nonoperative:
        return SourceRoleResult(text, ())

    masked: list[str] = []
    excluded: list[ExcludedSpan] = []
    fence_mark: str | None = None
    fence_length = 0
    for line_no, line in enumerate(text.splitlines(keepends=True), 1):
        body, ending = _split_ending(line)
        reason: str | None = None
        if fence_mark is not None:
            reason = "fenced"
            closing = _FENCE_CLOSE.match(body)
            if (closing and closing.group("marks")[0] == fence_mark
                    and len(closing.group("marks")) >= fence_length):
                fence_mark = None
                fence_length = 0
        elif _QUOTE.match(body):
            reason = "quoted"
        else:
            opening = _FENCE_OPEN.match(body)
            if opening:
                marks = opening.group("marks")
                # A CommonMark backtick opener cannot contain backticks in its info string.
                if marks[0] != "`" or "`" not in opening.group("info"):
                    fence_mark = marks[0]
                    fence_length = len(marks)
                    reason = "fenced"

        if reason is not None:
            masked.append(" " * len(body) + ending)
            if excluded and excluded[-1].reason == reason and excluded[-1].line_end == line_no - 1:
                prev = excluded[-1]
                excluded[-1] = ExcludedSpan(prev.line_start, line_no, reason)
            else:
                excluded.append(ExcludedSpan(line_no, line_no, reason))
        else:
            masked.append(line)
    return SourceRoleResult("".join(masked), tuple(excluded))
