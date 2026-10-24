from __future__ import annotations

import re

from .constraints import Modality, Rule, SourceSpan, normalize_effect


NEGATIVE_MODAL = re.compile(
    r"\b(must\s+not|shall\s+not|may\s+not|should\s+not|never|do\s+not|"
    r"is\s+prohibited\s+from|are\s+prohibited\s+from)\b",
    re.IGNORECASE,
)
PERMIT_MODAL = re.compile(
    r"\b(may|can|is\s+allowed\s+to|are\s+allowed\s+to|is\s+permitted\s+to|"
    r"are\s+permitted\s+to)\b",
    re.IGNORECASE,
)
REQUIRE_MODAL = re.compile(
    r"\b(must|shall|is\s+required\s+to|are\s+required\s+to)\b",
    re.IGNORECASE,
)
DELEGATION = re.compile(
    r"\b(ask|asks|asked|request|requests|requested|instruct|instructs|instructed|"
    r"delegate|delegates|delegated|authorize|authorizes|authorized|"
    r"cause|causes|caused)\b",
    re.IGNORECASE,
)
INDIRECT_SCOPE = re.compile(
    r"\b(indirectly|directly\s+or\s+indirectly|delegate|delegates|delegated|"
    r"authorize|authorizes|authorized|cause|causes|caused|instruct|instructs|instructed|"
    r"request|requests|requested|ask|asks|asked)\b",
    re.IGNORECASE,
)
CONDITION = re.compile(r"\b(if|when|provided\s+that|only\s+if)\b(.+)$", re.IGNORECASE)
EXCEPTION = re.compile(r"\b(unless|except(?:\s+when|\s+for)?|notwithstanding)\b(.+)$", re.IGNORECASE)
WORD = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
TO_ACTION = re.compile(
    r"\b(?:to|that\s+\w+\s+should)\s+([A-Za-z][A-Za-z0-9_-]*)\s+(.+?)(?:[.;]|$)",
    re.IGNORECASE,
)

LEADING_FILLER = {
    "directly", "indirectly", "ever", "generally", "normally", "only", "or", "and",
}
OBJECT_TRAIL = re.compile(
    r"\b(if|when|unless|except|provided\s+that|because|after|before|until|while)\b.*$",
    re.IGNORECASE,
)


def extract_rules(text: str) -> list[Rule]:
    rules: list[Rule] = []
    ordinal = 0
    for line_no, raw in enumerate(text.splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        for sentence in _sentences(raw):
            parsed = _parse_sentence(sentence, line_no, ordinal + 1)
            if parsed is None:
                continue
            ordinal += 1
            rules.append(parsed)
    return rules


def _sentences(raw: str) -> list[str]:
    return [
        part.strip(" \t-*#>")
        for part in re.split(r"(?<=[.!?;])\s+", raw)
        if part.strip(" \t-*#>")
    ]


def _parse_sentence(text: str, line: int, ordinal: int) -> Rule | None:
    match, modality = _find_modal(text)
    if match is None:
        return None

    subject = text[: match.start()].strip(" ,:")
    tail = text[match.end():].strip(" ,:")
    if not subject or not tail:
        return None

    condition = _capture_tail(CONDITION, tail)
    exception = _capture_tail(EXCEPTION, tail)
    core = OBJECT_TRAIL.sub("", tail).strip(" .,:;")
    indirect = bool(INDIRECT_SCOPE.search(core))

    action, obj, delegated_actor = _extract_effect(core, indirect)
    if not action:
        return None

    span = SourceSpan(line_start=line, line_end=line, text=text)
    return Rule(
        rule_id=f"R{ordinal:04d}",
        modality=modality,
        subject=_norm_phrase(subject),
        action=action,
        object=obj,
        effect_key=normalize_effect(action, obj),
        source=span,
        condition=condition,
        exception=exception,
        indirect=indirect,
        delegated_actor=delegated_actor,
        confidence=0.78 if indirect else 0.82,
    )


def _find_modal(text: str) -> tuple[re.Match[str] | None, Modality]:
    candidates: list[tuple[int, re.Match[str], Modality]] = []
    for regex, modality in (
        (NEGATIVE_MODAL, Modality.PROHIBIT),
        (PERMIT_MODAL, Modality.PERMIT),
        (REQUIRE_MODAL, Modality.REQUIRE),
    ):
        match = regex.search(text)
        if match:
            candidates.append((match.start(), match, modality))
    if not candidates:
        return None, Modality.UNKNOWN
    _, match, modality = min(candidates, key=lambda item: item[0])
    return match, modality


def _extract_effect(core: str, indirect: bool) -> tuple[str, str, str | None]:
    words = WORD.findall(core)
    while words and words[0].lower() in LEADING_FILLER:
        words.pop(0)
    if not words:
        return "", "", None

    if indirect:
        to_match = TO_ACTION.search(core)
        if to_match:
            action = _stem_action(to_match.group(1))
            obj = _norm_phrase(OBJECT_TRAIL.sub("", to_match.group(2)).strip(" .,:;"))
            before = core[: to_match.start()].strip()
            delegated_actor = _delegated_actor(before)
            return action, obj, delegated_actor

    action = _stem_action(words[0])
    obj = _norm_phrase(" ".join(words[1:]))
    return action, obj, None


def _delegated_actor(before: str) -> str | None:
    words = WORD.findall(before)
    if len(words) <= 1:
        return None
    return _norm_phrase(" ".join(words[1:]))


def _stem_action(action: str) -> str:
    word = action.lower()
    irregular = {
        "deletes": "delete",
        "deleted": "delete",
        "removes": "remove",
        "removed": "remove",
        "sends": "send",
        "sent": "send",
        "exports": "export",
        "exported": "export",
        "merges": "merge",
        "merged": "merge",
        "deploys": "deploy",
        "deployed": "deploy",
    }
    if word in irregular:
        return irregular[word]
    if word.endswith("ing") and len(word) > 5:
        return word[:-3]
    if word.endswith("ed") and len(word) > 4:
        return word[:-2]
    if word.endswith("s") and len(word) > 3:
        return word[:-1]
    return word


def _capture_tail(regex: re.Pattern[str], text: str) -> str | None:
    match = regex.search(text)
    return match.group(0).strip(" .,:;") if match else None


def _norm_phrase(value: str) -> str:
    return re.sub(r"\s+", " ", value.lower()).strip(" .,:;")
