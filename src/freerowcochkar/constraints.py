from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class Modality(str, Enum):
    PERMIT = "permit"
    PROHIBIT = "prohibit"
    REQUIRE = "require"
    UNKNOWN = "unknown"


class Relation(str, Enum):
    PERMITS = "permits"
    PROHIBITS = "prohibits"
    REQUIRES = "requires"
    DELEGATES = "delegates"
    EXCEPTS = "excepts"
    PRECEDES = "precedes"
    FALLBACK = "fallback"


@dataclass(frozen=True)
class SourceSpan:
    line_start: int
    line_end: int
    text: str


@dataclass(frozen=True)
class Rule:
    rule_id: str
    modality: Modality
    subject: str
    action: str
    object: str
    effect_key: str
    source: SourceSpan
    condition: str | None = None
    exception: str | None = None
    indirect: bool = False
    delegated_actor: str | None = None
    confidence: float = 0.5


@dataclass(frozen=True)
class ConstraintEdge:
    source: str
    target: str
    relation: Relation
    rule_id: str
    span: SourceSpan
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AdversarialPath:
    path_id: str
    category: str
    target_effect: str
    rule_ids: tuple[str, ...]
    spans: tuple[SourceSpan, ...]
    explanation: str
    hardening: str
    confidence: float


@dataclass
class ConstraintGraph:
    nodes: set[str] = field(default_factory=set)
    edges: list[ConstraintEdge] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)

    @classmethod
    def from_rules(cls, rules: Iterable[Rule]) -> "ConstraintGraph":
        graph = cls()
        for rule in rules:
            graph.add_rule(rule)
        return graph

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)
        subject = f"actor:{rule.subject}"
        effect = f"effect:{rule.effect_key}"
        self.nodes.update((subject, effect))

        relation = {
            Modality.PERMIT: Relation.PERMITS,
            Modality.PROHIBIT: Relation.PROHIBITS,
            Modality.REQUIRE: Relation.REQUIRES,
            Modality.UNKNOWN: Relation.REQUIRES,
        }[rule.modality]
        self.edges.append(
            ConstraintEdge(
                source=subject,
                target=effect,
                relation=relation,
                rule_id=rule.rule_id,
                span=rule.source,
            )
        )

        if rule.indirect:
            route = f"route:delegate:{rule.rule_id}"
            self.nodes.add(route)
            self.edges.append(
                ConstraintEdge(
                    source=subject,
                    target=route,
                    relation=Relation.DELEGATES,
                    rule_id=rule.rule_id,
                    span=rule.source,
                    metadata={"delegated_actor": rule.delegated_actor or "unspecified"},
                )
            )
            self.edges.append(
                ConstraintEdge(
                    source=route,
                    target=effect,
                    relation=relation,
                    rule_id=rule.rule_id,
                    span=rule.source,
                )
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "nodes": sorted(self.nodes),
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "modality": rule.modality.value,
                    "subject": rule.subject,
                    "action": rule.action,
                    "object": rule.object,
                    "effect_key": rule.effect_key,
                    "condition": rule.condition,
                    "exception": rule.exception,
                    "indirect": rule.indirect,
                    "delegated_actor": rule.delegated_actor,
                    "confidence": rule.confidence,
                    "source": {
                        "line_start": rule.source.line_start,
                        "line_end": rule.source.line_end,
                        "text": rule.source.text,
                    },
                }
                for rule in self.rules
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relation": edge.relation.value,
                    "rule_id": edge.rule_id,
                    "metadata": edge.metadata,
                    "span": {
                        "line_start": edge.span.line_start,
                        "line_end": edge.span.line_end,
                        "text": edge.span.text,
                    },
                }
                for edge in self.edges
            ],
            "paths": [
                {
                    "path_id": path.path_id,
                    "category": path.category,
                    "target_effect": path.target_effect,
                    "rule_ids": list(path.rule_ids),
                    "confidence": path.confidence,
                    "explanation": path.explanation,
                    "hardening": path.hardening,
                    "spans": [
                        {
                            "line_start": span.line_start,
                            "line_end": span.line_end,
                            "text": span.text,
                        }
                        for span in path.spans
                    ],
                }
                for path in self.search_literal_compliance_paths()
            ],
        }

    def search_literal_compliance_paths(self) -> list[AdversarialPath]:
        paths: list[AdversarialPath] = []
        prohibited = [r for r in self.rules if r.modality == Modality.PROHIBIT]
        permissive = [r for r in self.rules if r.modality == Modality.PERMIT]

        for ban in prohibited:
            for allow in permissive:
                if ban.effect_key != allow.effect_key:
                    continue
                # A ban with an explicit exception and a permission confined to
                # that same exception do not conflict. Only suppress when the
                # predicates match literally; semantic equivalence is outside
                # this deterministic parser's scope.
                if guard_relation(ban, allow) != "potential_conflict":
                    continue

                if allow.indirect and not ban.indirect and ban.subject == allow.subject:
                    paths.append(
                        AdversarialPath(
                            path_id=f"FRC-PATH-DELEGATE-{ban.rule_id}-{allow.rule_id}",
                            category="delegation_laundering",
                            target_effect=ban.effect_key,
                            rule_ids=(ban.rule_id, allow.rule_id),
                            spans=(ban.source, allow.source),
                            explanation=(
                                "The direct effect is prohibited, but a separate rule permits an "
                                "indirect or delegated route to the same normalized effect."
                            ),
                            hardening=(
                                "Bind the prohibition to the outcome: cover direct action, delegation, "
                                "authorization, requests, caused effects, and equivalent intermediated routes."
                            ),
                            confidence=min(ban.confidence, allow.confidence, 0.9),
                        )
                    )
                elif ban.subject == allow.subject:
                    paths.append(
                        AdversarialPath(
                            path_id=f"FRC-PATH-CONFLICT-{ban.rule_id}-{allow.rule_id}",
                            category="literal_permission_conflict",
                            target_effect=ban.effect_key,
                            rule_ids=(ban.rule_id, allow.rule_id),
                            spans=(ban.source, allow.source),
                            explanation=(
                                "The same actor is both prohibited and permitted to produce the same "
                                "normalized effect, with no graph-level precedence rule."
                            ),
                            hardening=(
                                "Add explicit precedence or narrow the permission with conditions that "
                                "cannot be read as superseding the prohibition."
                            ),
                            confidence=min(ban.confidence, allow.confidence, 0.92),
                        )
                    )
        return _dedupe_paths(paths)


def matching_exception_condition(ban: Rule, allow: Rule) -> bool:
    """Recognize one narrow, text-identical exception/permission pairing.

    For example, "must not X unless Y" and "may X when Y" are
    consistent. Similar-looking or paraphrased predicates stay unresolved.
    """
    if not ban.exception or not allow.condition:
        return False
    exception = re.fullmatch(r"unless\s+(.+)", ban.exception, re.IGNORECASE)
    condition = re.fullmatch(
        r"(?:when|if|only\s+if|provided\s+that)\s+(.+)",
        allow.condition,
        re.IGNORECASE,
    )
    if not exception or not condition:
        return False

    def normalize_predicate(value: str) -> str:
        return re.sub(r"\s+", " ", value.casefold()).strip(" .,:;")

    return normalize_predicate(exception.group(1)) == normalize_predicate(condition.group(1))


def guard_relation(ban: Rule, allow: Rule) -> str:
    """Return compatible, unresolved or potential_conflict for literal guards.

    This does not infer temporal, role, or semantic predicate equivalence.
    An unqualified rule potentially overlaps a qualified one; two distinct
    guards cannot be declared overlapping by this grammar.
    """
    if matching_exception_condition(ban, allow):
        return "compatible"
    if ban.exception and allow.condition:
        return "unresolved"
    if ban.condition and allow.exception:
        return "unresolved"
    if ban.condition and allow.condition:
        norm = lambda value: re.sub(r"\s+", " ", value.casefold()).strip(" .,:;")
        if norm(ban.condition) != norm(allow.condition):
            return "unresolved"
    if ban.exception and allow.exception and ban.exception != allow.exception:
        return "unresolved"
    return "potential_conflict"


def normalize_effect(action: str, obj: str) -> str:
    action = _normalize_words(action)
    obj = _normalize_words(obj)
    return f"{action}:{obj}".strip(":")


def _normalize_words(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9_ -]+", " ", value)
    value = re.sub(r"\b(the|a|an|their|its|your)\b", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def _dedupe_paths(paths: list[AdversarialPath]) -> list[AdversarialPath]:
    seen: set[tuple[str, tuple[str, ...]]] = set()
    out: list[AdversarialPath] = []
    for path in paths:
        key = (path.category, path.rule_ids)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out
