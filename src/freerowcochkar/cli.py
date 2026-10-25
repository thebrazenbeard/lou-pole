from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze, scan_coverage, source_provenance
from .constraints import ConstraintGraph
from .rules import extract_rules


def _render_text(report) -> str:
    lines = [
        f"FreeRowCochkar profile={report.profile} risk={report.risk_score}/100 "
        f"findings={len(report.findings)}"
    ]
    if report.intent:
        lines.append(f"Declared intent: {report.intent}")
    lines.append(
        f"Coverage: {report.coverage.get('extracted_rule_count', 0)} extracted rules; "
        f"{report.coverage.get('unparsed_normative_clause_count', 0)} unparsed normative-looking clauses. "
        "Zero findings is not a safety determination."
    )

    for i, finding in enumerate(report.findings, 1):
        lines.append("")
        lines.append(
            f"{i}. [{finding.severity.value.upper()}] {finding.category}: {finding.title}"
        )
        for ev in finding.evidence:
            lines.append(f"   L{ev.line_start}: {ev.text}")
        lines.append(f"   Why: {finding.why_it_matters}")
        lines.append(f"   Literalist path: {finding.literalist_path}")
        lines.append(f"   Harden: {finding.hardening}")
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
    parser.add_argument("--intent", help="Optional plain-language intended invariant.")
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
    if args.path and args.path != "-":
        text = Path(args.path).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    if args.graph_json:
        graph = ConstraintGraph.from_rules(extract_rules(
            text, include_nonoperative=args.include_nonoperative
        ))
        payload = graph.to_dict()
        payload["coverage"] = scan_coverage(
            text, include_nonoperative=args.include_nonoperative
        )
        if args.provenance or args.source_url is not None:
            payload["source"] = source_provenance(text, source_url=args.source_url)
        print(json.dumps(payload, indent=2))
        return 1 if graph.search_literal_compliance_paths() else 0

    report = analyze(
        text, profile=args.profile, intent=args.intent,
        include_source=args.provenance, source_url=args.source_url,
        include_nonoperative=args.include_nonoperative,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_text(report))
    return 1 if any(f.severity.value == "high" for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
