from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Evidence:
    line_start: int
    line_end: int
    text: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: Severity
    title: str
    evidence: tuple[Evidence, ...]
    why_it_matters: str
    literalist_path: str
    hardening: str
    confidence: float = 0.7

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["severity"] = self.severity.value
        return out


@dataclass
class AnalysisReport:
    profile: str
    findings: list[Finding] = field(default_factory=list)
    intent: str | None = None
    coverage: dict[str, Any] = field(default_factory=dict)
    source: dict[str, str] | None = None

    @property
    def risk_score(self) -> int:
        weights = {
            Severity.LOW: 1,
            Severity.MEDIUM: 3,
            Severity.HIGH: 6,
        }
        raw = sum(weights[f.severity] for f in self.findings)
        return min(100, raw * 4)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "profile": self.profile,
            "intent": self.intent,
            "risk_score": self.risk_score,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "coverage": self.coverage,
        }
        if self.source is not None:
            result["source"] = self.source
        return result
