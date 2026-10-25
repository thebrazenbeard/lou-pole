from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Iterable

from .constraints import ConstraintGraph, Modality, guard_relation
from .models import AnalysisReport, Evidence, Finding, Severity
from .rules import extract_rules


NORMATIVE_RE = re.compile(
    r"^only\s+(?!if\b)|\b(must(?:\s+not)?|shall(?:\s+not)?|may(?:\s+not)?|should(?:\s+not)?|"
    r"can(?:\s+not|not|['’]t)|(?:is|are)\s+not\s+(?:allowed|permitted)\s+to|"
    r"required(?:\s+to)?|prohibited|forbidden|only\s+if|never|always|do\s+not)\b",
    re.IGNORECASE,
)
NEGATIVE_RE = re.compile(
    r"\b(must\s+not|shall\s+not|may\s+not|should\s+not|"
    r"can(?:\s+not|not|['’]t)|(?:is|are)\s+not\s+(?:allowed|permitted)\s+to|"
    r"prohibited|forbidden|never|do\s+not)\b",
    re.IGNORECASE,
)
PERMISSIVE_RE = re.compile(r"\b(may|can|allowed|permitted|optional)\b", re.IGNORECASE)
EXCEPTION_RE = re.compile(
    r"\b(unless|except(?:\s+when|\s+for)?|other\s+than|notwithstanding|save\s+for)\b",
    re.IGNORECASE,
)
VAGUE_RE = re.compile(
    r"\b(appropriate|reasonable|material|meaningful|relevant|significant|normally|"
    r"generally|when\s+possible|if\s+possible|as\s+needed|as\s+appropriate|timely|"
    r"substantial|sufficient|necessary)\b",
    re.IGNORECASE,
)
DEPENDENCY_RE = re.compile(
    r"\b(use|consult|read|query|call|fetch|connect\s+to|retrieve\s+from)\b.{0,50}\b"
    r"(service|database|api|provider|repository|repo|tool|connector|server|endpoint|file)\b",
    re.IGNORECASE,
)
FAILURE_LANGUAGE_RE = re.compile(
    r"\b(unavailable|fails?|failure|timeout|missing|absent|unknown|fallback|retry|error)\b",
    re.IGNORECASE,
)
INDIRECT_SCOPE_RE = re.compile(
    r"\b(directly\s+or\s+indirectly|indirectly|cause(?:s|d|ing)?|delegate(?:s|d|ing)?|"
    r"on\s+(?:their|its|your)\s+behalf|through\s+(?:a|an|the)\s+"
    r"(?:agent|tool|service|third[- ]party))\b",
    re.IGNORECASE,
)
SENSITIVE_ACTION_RE = re.compile(
    r"\b(delete|remove|merge|deploy|publish|send|disclose|export|transfer|execute|"
    r"modify|change|grant|revoke|approve|install|activate|disable|bypass)\w*\b",
    re.IGNORECASE,
)
CODE_SWALLOW_RE = re.compile(
    r"except(?:\s+Exception(?:\s+as\s+\w+)?)?\s*:\s*(?:#.*\n\s*)?pass\b",
    re.IGNORECASE,
)
CODE_BROAD_EXCEPT_RE = re.compile(r"except\s+Exception(?:\s+as\s+\w+)?\s*:", re.IGNORECASE)
CODE_DEFAULT_ALLOW_RE = re.compile(
    r"\b(default[_-]?allow|allow[_-]?all|fail[_-]?open)\b|"
    r"except[^:]*:\s*(?:\n\s*)?return\s+True\b",
    re.IGNORECASE,
)

STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "if", "in",
    "is", "it", "of", "on", "or", "that", "the", "this", "to", "when", "with",
    "must", "shall", "may", "should", "not", "do", "never", "always", "only",
}


@dataclass(frozen=True)
class Clause:
    line: int
    text: str

    @property
    def negative(self) -> bool:
        return bool(NEGATIVE_RE.search(self.text))

    @property
    def permissive(self) -> bool:
        return bool(PERMISSIVE_RE.search(self.text))

    @property
    def terms(self) -> set[str]:
        words = re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", self.text.lower())
        return {w for w in words if w not in STOPWORDS}


def _clauses(text: str) -> list[Clause]:
    out: list[Clause] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        chunks = re.split(r"(?<=[.!?;])\s+", raw)
        for chunk in chunks:
            chunk = chunk.strip(" \t-*#>")
            if chunk:
                out.append(Clause(line_no, chunk))
    return out


def _overlap(a: Clause, b: Clause) -> float:
    if not a.terms or not b.terms:
        return 0.0
    jaccard = len(a.terms & b.terms) / len(a.terms | b.terms)
    seq = SequenceMatcher(None, " ".join(sorted(a.terms)), " ".join(sorted(b.terms))).ratio()
    return max(jaccard, seq * 0.75)


def _same_or_narrower_effect_scope(first: str, second: str) -> bool:
    """Compare literal objects, allowing an explicit ``for <purpose>`` scope.

    Other overlapping vocabulary (for example customer versus audit records)
    is insufficient evidence for a HIGH contradiction.
    """
    if first == second:
        return True
    return first.startswith(f"{second} for ") or second.startswith(f"{first} for ")


def _ev(clause: Clause) -> tuple[Evidence, ...]:
    return (Evidence(clause.line, clause.line, clause.text),)


def scan_coverage(text: str) -> dict[str, object]:
    """Expose observable parser gaps without claiming semantic completeness."""
    skipped = [
        {"line_start": clause.line, "line_end": clause.line, "text": clause.text}
        for clause in _clauses(text)
        if NORMATIVE_RE.search(clause.text) and not extract_rules(clause.text)
    ]
    return {
        "extracted_rule_count": len(extract_rules(text)),
        "unparsed_normative_clause_count": len(skipped),
        "unparsed_normative_clauses": skipped,
        "notice": (
            "Heuristic extraction is not a safety determination. Zero findings or zero "
            "unparsed clauses does not prove completeness, compliance, or absence of loopholes."
        ),
    }


class Analyzer:
    """Deterministic first-pass loophole auditor.

    Findings are candidates, not conclusions. The engine identifies places where
    literal compliance may diverge from intended behavior so the rule system can
    be hardened and regression-tested.
    """

    def analyze(
        self,
        text: str,
        *,
        profile: str = "auto",
        intent: str | None = None,
    ) -> AnalysisReport:
        if profile == "auto":
            profile = self._detect_profile(text)

        clauses = _clauses(text)
        findings: list[Finding] = []
        findings.extend(self._ambiguous_scope(clauses))
        findings.extend(self._unbounded_exceptions(clauses))
        findings.extend(self._precedence_and_collision(clauses))
        findings.extend(self._unresolved_guard_scope(clauses))
        findings.extend(self._fallback_gaps(clauses))
        findings.extend(self._indirect_effect_gaps(clauses))
        findings.extend(self._constraint_graph_findings(text))

        if profile in {"code", "mixed"}:
            findings.extend(self._code_findings(text))

        findings.sort(
            key=lambda f: (
                {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}[f.severity],
                f.rule_id,
            )
        )
        return AnalysisReport(
            profile=profile,
            findings=findings,
            intent=intent,
            coverage=scan_coverage(text),
        )

    @staticmethod
    def _detect_profile(text: str) -> str:
        code_markers = (
            "def ", "class ", "function ", "=>", "except ", "try:", "if (",
            "return ", "const ", "let ", "var ", "SELECT ", "FROM ",
        )
        hits = sum(marker in text for marker in code_markers)
        normative = len(NORMATIVE_RE.findall(text))
        if hits >= 2 and normative >= 1:
            return "mixed"
        if hits >= 2:
            return "code"
        return "instructions"

    def _ambiguous_scope(self, clauses: Iterable[Clause]) -> list[Finding]:
        out: list[Finding] = []
        for c in clauses:
            vague = VAGUE_RE.search(c.text)
            if NORMATIVE_RE.search(c.text) and vague:
                term = vague.group(0)
                out.append(Finding(
                    rule_id="FRC-SCOPE-001",
                    category="ambiguous_scope",
                    severity=Severity.MEDIUM,
                    title=f"Normative rule depends on undefined qualifier: {term!r}",
                    evidence=_ev(c),
                    why_it_matters=(
                        "A mandatory or prohibitive instruction changes meaning depending on "
                        "an undefined judgment call."
                    ),
                    literalist_path=(
                        f"A literal reader can choose a favorable interpretation of {term!r} "
                        "while claiming compliance."
                    ),
                    hardening=(
                        f"Define {term!r} with observable criteria, an accountable decision-maker, "
                        "and a fail-closed rule for borderline cases."
                    ),
                    confidence=0.86,
                ))
        return out

    def _unbounded_exceptions(self, clauses: Iterable[Clause]) -> list[Finding]:
        out: list[Finding] = []
        for c in clauses:
            marker = EXCEPTION_RE.search(c.text)
            if marker and NORMATIVE_RE.search(c.text):
                out.append(Finding(
                    rule_id="FRC-EXC-001",
                    category="exception_surface",
                    severity=Severity.MEDIUM,
                    title="Exception path can outrank the base rule",
                    evidence=_ev(c),
                    why_it_matters=(
                        "Exception language creates a second path through the policy. If its scope, "
                        "authority, or duration is not explicit, it can swallow the base rule."
                    ),
                    literalist_path=(
                        f"Treat the {marker.group(0)!r} clause as the controlling path and satisfy "
                        "its easiest literal reading."
                    ),
                    hardening=(
                        "Name who may invoke the exception, enumerate qualifying conditions, define "
                        "its duration and scope, and state which invariants remain non-waivable."
                    ),
                    confidence=0.78,
                ))
        return out

    def _precedence_and_collision(self, clauses: list[Clause]) -> list[Finding]:
        out: list[Finding] = []
        normative = [
            (clause, extract_rules(clause.text))
            for clause in clauses if NORMATIVE_RE.search(clause.text)
        ]
        for i, (a, parsed_a) in enumerate(normative):
            for b, parsed_b in normative[i + 1:]:
                # Lexical overlap is not evidence that two actors or two
                # separately scoped effects contradict each other. Keep HIGH
                # precedence findings to structurally supported comparisons.
                if len(parsed_a) != 1 or len(parsed_b) != 1:
                    continue
                rule_a, rule_b = parsed_a[0], parsed_b[0]
                if rule_a.subject != rule_b.subject or rule_a.action != rule_b.action:
                    continue
                if not _same_or_narrower_effect_scope(rule_a.object, rule_b.object):
                    continue
                if {rule_a.modality, rule_b.modality} != {Modality.PROHIBIT, Modality.PERMIT}:
                    continue
                ban = rule_a if rule_a.modality == Modality.PROHIBIT else rule_b
                allow = rule_b if rule_a.modality == Modality.PROHIBIT else rule_a
                if guard_relation(ban, allow) != "potential_conflict":
                    continue
                score = _overlap(a, b)
                if score < 0.34:
                    continue
                opposed = a.negative != b.negative and (
                    a.permissive or b.permissive or bool(NORMATIVE_RE.search(a.text)) or bool(NORMATIVE_RE.search(b.text))
                )
                exception_collision = (
                    (EXCEPTION_RE.search(a.text) or EXCEPTION_RE.search(b.text))
                    and a.negative != b.negative
                )
                if not (opposed or exception_collision):
                    continue
                out.append(Finding(
                    rule_id="FRC-PREC-001",
                    category="precedence_collision",
                    severity=Severity.HIGH,
                    title="Overlapping rules point in different directions",
                    evidence=(
                        Evidence(a.line, a.line, a.text),
                        Evidence(b.line, b.line, b.text),
                    ),
                    why_it_matters=(
                        "A literal actor can select the more permissive rule unless precedence is explicit."
                    ),
                    literalist_path=(
                        "Cite the rule that permits the desired behavior and treat the conflicting "
                        "restriction as lower-priority or inapplicable."
                    ),
                    hardening=(
                        "State explicit precedence, narrow each rule's scope, and add a conflict rule "
                        "for unresolved overlaps."
                    ),
                    confidence=min(0.96, 0.62 + score),
                ))
        return out

    def _unresolved_guard_scope(self, clauses: list[Clause]) -> list[Finding]:
        parsed = [(c, extract_rules(c.text)) for c in clauses if NORMATIVE_RE.search(c.text)]
        out: list[Finding] = []
        for i, (a, left) in enumerate(parsed):
            if len(left) != 1:
                continue
            for b, right in parsed[i + 1:]:
                if len(right) != 1:
                    continue
                one, two = left[0], right[0]
                if {one.modality, two.modality} != {Modality.PROHIBIT, Modality.PERMIT}:
                    continue
                if one.subject != two.subject or one.action != two.action:
                    continue
                if not _same_or_narrower_effect_scope(one.object, two.object):
                    continue
                ban = one if one.modality == Modality.PROHIBIT else two
                allow = two if one.modality == Modality.PROHIBIT else one
                if guard_relation(ban, allow) != "unresolved":
                    continue
                out.append(Finding(
                    rule_id="FRC-GUARD-001",
                    category="guard_overlap_unknown",
                    severity=Severity.MEDIUM,
                    title="Conditions or exceptions may not overlap; conflict is unproven",
                    evidence=(Evidence(a.line, a.line, a.text), Evidence(b.line, b.line, b.text)),
                    why_it_matters=(
                        "The deterministic parser cannot establish whether the different guards "
                        "permit and prohibit the same action in the same state."
                    ),
                    literalist_path="No reachable violating path was established by these clauses.",
                    hardening="Define guard precedence and disjointness in a verifiable rule model.",
                    confidence=0.6,
                ))
        return out

    def _fallback_gaps(self, clauses: list[Clause]) -> list[Finding]:
        out: list[Finding] = []
        for i, c in enumerate(clauses):
            dependency = DEPENDENCY_RE.search(c.text)
            if not (NORMATIVE_RE.search(c.text) and dependency):
                continue

            start = max(0, i - 2)
            stop = min(len(clauses), i + 3)
            local_context = " ".join(item.text for item in clauses[start:stop])
            if FAILURE_LANGUAGE_RE.search(local_context):
                continue

            out.append(Finding(
                rule_id="FRC-FAIL-001",
                category="failure_mode_gap",
                severity=Severity.HIGH,
                title="Required dependency has no nearby stated failure behavior",
                evidence=_ev(c),
                why_it_matters=(
                    "The rule requires an external dependency but its local rule context does not say "
                    "what happens when that dependency cannot be used."
                ),
                literalist_path=(
                    "Treat dependency failure as releasing the obligation, or substitute an "
                    "unapproved source because the failure path is undefined."
                ),
                hardening=(
                    "Specify fail-closed or fail-open behavior, permitted substitutes, retry bounds, "
                    "and the exact status to report when the dependency is unavailable."
                ),
                confidence=0.86,
            ))
        return out

    def _indirect_effect_gaps(self, clauses: list[Clause]) -> list[Finding]:
        out: list[Finding] = []
        for c in clauses:
            if not (c.negative and SENSITIVE_ACTION_RE.search(c.text)):
                continue
            if INDIRECT_SCOPE_RE.search(c.text):
                continue
            out.append(Finding(
                rule_id="FRC-INDIRECT-001",
                category="indirect_effect_gap",
                severity=Severity.MEDIUM,
                title="Direct prohibition does not explicitly cover causing the same effect indirectly",
                evidence=_ev(c),
                why_it_matters=(
                    "A rule can forbid an actor from performing an effect while remaining silent about "
                    "delegating, routing, requesting, or otherwise causing that same effect."
                ),
                literalist_path=(
                    "Avoid performing the prohibited action directly and instead cause another actor, "
                    "tool, or service to produce the same outcome."
                ),
                hardening=(
                    "State whether the prohibition covers direct and indirect action, delegation, requests, "
                    "authorization, attempted circumvention, and equivalent downstream effects."
                ),
                confidence=0.72,
            ))
        return out

    def _constraint_graph_findings(self, text: str) -> list[Finding]:
        rules = extract_rules(text)
        graph = ConstraintGraph.from_rules(rules)
        out: list[Finding] = []
        for path in graph.search_literal_compliance_paths():
            evidence = tuple(
                Evidence(span.line_start, span.line_end, span.text)
                for span in path.spans
            )
            severity = (
                Severity.HIGH
                if path.category in {"delegation_laundering", "literal_permission_conflict"}
                else Severity.MEDIUM
            )
            out.append(Finding(
                rule_id=path.path_id,
                category=path.category,
                severity=severity,
                title=f"Constraint graph exposes path to prohibited effect: {path.target_effect}",
                evidence=evidence,
                why_it_matters=path.explanation,
                literalist_path=(
                    "Compose the cited rules exactly as written so that the permitted route "
                    "produces an effect restricted elsewhere."
                ),
                hardening=path.hardening,
                confidence=path.confidence,
            ))
        return out

    def _code_findings(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()

        def evidence_for(match: re.Match[str]) -> tuple[Evidence, ...]:
            line = text[:match.start()].count("\n") + 1
            snippet = lines[line - 1].strip() if line <= len(lines) else match.group(0).strip()
            return (Evidence(line, line, snippet),)

        for match in CODE_SWALLOW_RE.finditer(text):
            out.append(Finding(
                rule_id="FRC-CODE-001",
                category="silent_failure",
                severity=Severity.HIGH,
                title="Exception is swallowed",
                evidence=evidence_for(match),
                why_it_matters=(
                    "A failed invariant can be converted into apparent success or continued execution."
                ),
                literalist_path=(
                    "Trigger the exceptional path and rely on the program continuing without enforcing "
                    "the intended check."
                ),
                hardening=(
                    "Catch the narrow expected exception, record it, and fail closed or return an "
                    "explicit error state."
                ),
                confidence=0.95,
            ))

        for match in CODE_DEFAULT_ALLOW_RE.finditer(text):
            out.append(Finding(
                rule_id="FRC-CODE-002",
                category="fail_open",
                severity=Severity.HIGH,
                title="Code contains an allow-by-default or fail-open signal",
                evidence=evidence_for(match),
                why_it_matters=(
                    "A missing, malformed, or exceptional state may grant access instead of preserving "
                    "the intended restriction."
                ),
                literalist_path=(
                    "Reach the default or error path rather than satisfying the normal authorization path."
                ),
                hardening=(
                    "Make denial the default, require explicit positive authorization, and test malformed "
                    "and missing-state cases."
                ),
                confidence=0.90,
            ))

        swallowed = [m.span() for m in CODE_SWALLOW_RE.finditer(text)]
        for match in CODE_BROAD_EXCEPT_RE.finditer(text):
            if any(a <= match.start() <= b for a, b in swallowed):
                continue
            out.append(Finding(
                rule_id="FRC-CODE-003",
                category="overbroad_error_boundary",
                severity=Severity.MEDIUM,
                title="Broad exception boundary may erase distinctions between failure modes",
                evidence=evidence_for(match),
                why_it_matters=(
                    "Security, validation, availability, and programmer errors can become one generic path."
                ),
                literalist_path=(
                    "Cause an unexpected exception that is handled as if it were an expected recoverable case."
                ),
                hardening=(
                    "Catch only expected exception types and keep authorization and validation failures "
                    "distinct from availability failures."
                ),
                confidence=0.82,
            ))
        return out


def analyze(text: str, *, profile: str = "auto", intent: str | None = None) -> AnalysisReport:
    return Analyzer().analyze(text, profile=profile, intent=intent)
