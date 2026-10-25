from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import unicodedata

from .analyzer import NORMATIVE_RE, _clauses, analyze, scan_coverage, source_provenance
from .constraints import ConstraintGraph
from .rules import extract_rules
from .source_roles import mask_nonoperative_markdown


# Bounded CLI admission control. The library analyzer remains an explicitly
# unbounded, caller-managed API; these are intentionally conservative ceilings.
MAX_SOURCE_BYTES = 128 * 1024
MAX_LINE_BYTES = 8 * 1024
MAX_TOTAL_CLAUSES = 1024
MAX_OPERATIVE_CLAUSES = 64
MAX_EXTRACTED_RULES = 40
MAX_RULE_PAIRS = 400
MAX_METADATA_BYTES = 2 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024


class IncompleteAnalysis(Exception):
    """The CLI cannot safely complete this analysis within its resource budget."""


def _read_source(path: str | None) -> str:
    if path and path != "-":
        # On POSIX, nonblocking open prevents a FIFO from hanging before fstat
        # can reject it. NOFOLLOW rejects final symlinks where supported.
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise IncompleteAnalysis("input path is not a regular file")
            if info.st_size > MAX_SOURCE_BYTES:
                raise IncompleteAnalysis(f"input exceeds {MAX_SOURCE_BYTES} UTF-8 bytes")
            data = stream.read(MAX_SOURCE_BYTES + 1)
    else:
        # The binary stream prevents Python's stdin surrogateescape decoder
        # from silently treating invalid UTF-8 as innocuous policy text.
        binary_stream = getattr(sys.stdin, "buffer", None)
        if binary_stream is not None:
            data = binary_stream.read(MAX_SOURCE_BYTES + 1)
        else:
            # Support a caller-owned text StringIO (including existing tests).
            entered = sys.stdin.read(MAX_SOURCE_BYTES + 1)
            try:
                data = entered.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise IncompleteAnalysis("stdin is not valid UTF-8") from exc

    if len(data) > MAX_SOURCE_BYTES:
        raise IncompleteAnalysis(f"input exceeds {MAX_SOURCE_BYTES} UTF-8 bytes")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise IncompleteAnalysis("input is not valid UTF-8") from exc


def _check_complexity(text: str, *, include_nonoperative: bool) -> list:
    for line in text.splitlines():
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise IncompleteAnalysis(f"input contains a line over {MAX_LINE_BYTES} UTF-8 bytes")

    operative = mask_nonoperative_markdown(
        text, include_nonoperative=include_nonoperative
    ).masked_text
    clauses = _clauses(operative)
    if len(clauses) > MAX_TOTAL_CLAUSES:
        raise IncompleteAnalysis(f"input has over {MAX_TOTAL_CLAUSES} operative text clauses")
    if sum(bool(NORMATIVE_RE.search(clause.text)) for clause in clauses) > MAX_OPERATIVE_CLAUSES:
        raise IncompleteAnalysis(f"input has over {MAX_OPERATIVE_CLAUSES} operative clauses")
    rules = extract_rules(operative, include_nonoperative=True)
    if len(rules) > MAX_EXTRACTED_RULES:
        raise IncompleteAnalysis(f"input has over {MAX_EXTRACTED_RULES} extracted rules")
    if len(rules) * (len(rules) - 1) // 2 > MAX_RULE_PAIRS:
        raise IncompleteAnalysis(f"input exceeds {MAX_RULE_PAIRS} possible rule pairs")
    return rules


def _bounded_output(output: str) -> None:
    if len(output.encode("utf-8")) > MAX_REPORT_BYTES:
        raise IncompleteAnalysis(f"report exceeds {MAX_REPORT_BYTES} UTF-8 bytes")
    print(output)


def _terminal_safe(value: object) -> str:
    """Keep untrusted policy prose from operating the reader's terminal."""
    chars = []
    for char in str(value):
        if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            code = ord(char)
            chars.append(f"\\x{code:02x}" if code <= 255 else f"\\u{code:04x}")
        else:
            chars.append(char)
    return "".join(chars)


def _render_text(report) -> str:
    lines = [
        f"FreeRowCochkar profile={_terminal_safe(report.profile)} risk={report.risk_score}/100 "
        f"findings={len(report.findings)}"
    ]
    if report.intent is not None:
        lines.append(f"Declared intent (not evaluated): {_terminal_safe(report.intent)}")
    lines.append(
        f"Coverage: {report.coverage.get('extracted_rule_count', 0)} extracted rules; "
        f"{report.coverage.get('unparsed_normative_clause_count', 0)} unparsed normative-looking clauses. "
        "Zero findings is not a safety determination."
    )

    for i, finding in enumerate(report.findings, 1):
        lines.append("")
        lines.append(
            f"{i}. [{finding.severity.value.upper()}] {_terminal_safe(finding.category)}: {_terminal_safe(finding.title)}"
        )
        for ev in finding.evidence:
            lines.append(f"   L{ev.line_start}: {_terminal_safe(ev.text)}")
        lines.append(f"   Why: {_terminal_safe(finding.why_it_matters)}")
        lines.append(f"   Literalist path: {_terminal_safe(finding.literalist_path)}")
        lines.append(f"   Harden: {_terminal_safe(finding.hardening)}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="freerowcochkar",
        description=(
            "Defensive adversarial audit for literal-compliance loopholes in instructions, "
            "policies, specifications, and code."
        ),
    )
    parser.add_argument("path", nargs="?", help="File to audit. Omit or use '-' for stdin.")
    parser.add_argument(
        "--profile",
        choices=("auto", "instructions", "code", "mixed"),
        default="auto",
        help="Analysis profile.",
    )
    parser.add_argument(
        "--intent", help="Optional plain-language intended invariant (annotation only; not evaluated).",
    )
    parser.add_argument(
        "--provenance", action="store_true",
        help="Include a SHA-256 digest of the analyzed UTF-8 text in JSON output.",
    )
    parser.add_argument(
        "--source-url", help="Optional caller-declared source URL (not fetched or verified).",
    )
    parser.add_argument(
        "--include-nonoperative", action="store_true",
        help="Analyze quoted and fenced Markdown as operative (explicit caller override).",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable finding JSON.")
    parser.add_argument(
        "--graph-json",
        action="store_true",
        help="Emit extracted rules, graph edges, and adversarial paths as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        for label, value in (("intent", args.intent), ("source URL", args.source_url)):
            if value is None:
                continue
            try:
                metadata_bytes = value.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise IncompleteAnalysis(f"{label} is not valid UTF-8") from exc
            if len(metadata_bytes) > MAX_METADATA_BYTES:
                raise IncompleteAnalysis(f"{label} exceeds {MAX_METADATA_BYTES} UTF-8 bytes")

        text = _read_source(args.path)
        rules = _check_complexity(text, include_nonoperative=args.include_nonoperative)

        if args.graph_json:
            graph = ConstraintGraph.from_rules(rules)
            payload = graph.to_dict()
            payload["coverage"] = scan_coverage(
                text, include_nonoperative=args.include_nonoperative,
                intent=args.intent,
            )
            if args.intent is not None:
                payload["intent"] = args.intent
            if args.provenance or args.source_url is not None:
                payload["source"] = source_provenance(text, source_url=args.source_url)
            _bounded_output(json.dumps(payload, indent=2))
            return 1 if payload["paths"] else 0

        report = analyze(
            text, profile=args.profile, intent=args.intent,
            include_source=args.provenance, source_url=args.source_url,
            include_nonoperative=args.include_nonoperative,
        )
        _bounded_output(json.dumps(report.to_dict(), indent=2) if args.json else _render_text(report))
        return 1 if any(f.severity.value == "high" for f in report.findings) else 0
    except (IncompleteAnalysis, OSError) as exc:
        print(f"INCOMPLETE_UNKNOWN: analysis not completed: {_terminal_safe(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
