from __future__ import annotations

import re

from .constraints import Modality, Rule, SourceSpan, normalize_effect
from .source_roles import mask_nonoperative_markdown


NEGATIVE_MODAL = re.compile(
    r"\b(must\s+(?:not|never)|shall\s+(?:not|never)|"
    r"may\s+(?:not|never)|should\s+(?:not|never)|"
    r"can(?:\s+not|not|['’]t)|"
    r"(?:is|are)\s+(?:not|never)\s+(?:allowed|permitted)\s+to|"
    r"never|do\s+not|"
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
APPROVAL_QUALIFIER = (
    r"without\s+(?:(?:prior|explicit|written)\s+){0,3}"
    r"(?:approval|authorization|permission|consent)"
)
CONDITION = re.compile(
    rf"\b(only\s+if|provided\s+that|if|when|until|after|before|while)\b(.+)$|"
    rf"\b{APPROVAL_QUALIFIER}\b.*$",
    re.IGNORECASE,
)
EXCEPTION = re.compile(r"\b(unless|except(?:\s+when|\s+for)?|notwithstanding)\b(.+)$", re.IGNORECASE)
WORD = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
INLINE_SUBJECT_MARKUP = re.compile(
    r"(?<![\w\\*_`])(?P<marker>\*{1,3}|_{1,3}|`)"
    r"(?P<label>[A-Za-z][A-Za-z0-9_ -]*?)"
    r"(?P=marker)(?![\w*_`])"
)
TO_ACTION = re.compile(
    r"\b(?:to|that\s+\w+\s+should)\s+([A-Za-z][A-Za-z0-9_-]*)\s+(.+?)(?:[.;]|$)",
    re.IGNORECASE,
)

LEADING_FILLER = {
    "directly", "indirectly", "ever", "generally", "normally", "only", "or", "and",
}
OBJECT_TRAIL = re.compile(
    rf"\b(only\s+if|provided\s+that|if|when|unless|except|because|after|before|until|while|{APPROVAL_QUALIFIER})\b.*$",
    re.IGNORECASE,
)
UNSUPPORTED_PASSIVE = re.compile(
    r"^be\s+(?:sent|paid|made|given|\w+(?:ed|en))\b",
    re.IGNORECASE,
)
UNSUPPORTED_CAUSATIVE_HAVE = re.compile(
    r"^have\s+.+\b(?:delete|send|export|transfer|remove|modify|approve)\b",
    re.IGNORECASE,
)
LEADING_NO_MODAL = re.compile(
    r"^no\s+(?P<subject>[A-Za-z][A-Za-z0-9_ -]*?)\s+"
    r"(?P<modal>may|can|must|shall)\s+(?P<tail>.+)$",
    re.IGNORECASE,
)
UNKNOWN_NEGATIVE_QUANTIFIER = re.compile(
    r"^(?:nobody\b|no[ -]one\b|none\b|neither\b|not\s+a\s+single\b)",
    re.IGNORECASE,
)
UNSUPPORTED_NEGATED_TAIL = re.compile(
    r"^(?:by\s+no\s+means|under\s+no\s+circumstances|no\s+longer)\b",
    re.IGNORECASE,
)
SUBORDINATE_PREFIX = re.compile(
    r"\b(?:because|so\s+long\s+as|provided\s+that|such\s+that)\b",
    re.IGNORECASE,
)
ABSENCE_OF_DUTY = re.compile(
    r"\b(?:do\s+not\s+(?:have|need)\s+to|never\s+have\s+to)\b",
    re.IGNORECASE,
)
DESCRIPTIVE_NEVER = re.compile(
    r"\b(?:is|are|was|were)\s+never\s+(?!allowed\s+to\b|permitted\s+to\b)",
    re.IGNORECASE,
)


def extract_rules(text: str, *, include_nonoperative: bool = False) -> list[Rule]:
    # Lexically isolated quotes and fences are unverified as operative policy.
    # Preserve offsets so evidence still points to the original source lines.
    text = mask_nonoperative_markdown(
        text, include_nonoperative=include_nonoperative
    ).masked_text
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
    return [part.strip() for part in re.split(r"(?<=[.!?;])\s+", raw) if part.strip()]


def _parse_sentence(text: str, line: int, ordinal: int) -> Rule | None:
    source_text = text
    # Treat Markdown structure as presentation while retaining literal evidence.
    text = re.sub(r"^(?:(?:[-*+]\s+)|(?:#+\s+)|(?:>+\s*))*", "", text)
    text = _strip_markdown_wrappers(text)
    if UNKNOWN_NEGATIVE_QUANTIFIER.match(text):
        return None
    if DESCRIPTIVE_NEVER.search(text):
        # "Silence is never approval" is a descriptive identity assertion,
        # not a ban on the action "approval". Unsupported forms remain unparsed.
        return None
    leading_no = LEADING_NO_MODAL.match(text)
    if leading_no:
        if leading_no.group("modal").lower() not in {"may", "can"}:
            # "No actor must..." denies an obligation; it is not an action ban.
            return None
        subject = leading_no.group("subject")
        tail = leading_no.group("tail").strip(" ,:")
        if tail.lower().startswith(("not ", "never ")):
            return None
        modality = Modality.PROHIBIT
    else:
        match, modality = _find_modal(text)
        if match is None:
            return None
        no_duty = ABSENCE_OF_DUTY.search(text)
        if no_duty and no_duty.start() <= match.start():
            # "Not required to act" is not a prohibition of the action.
            return None
        subordinate = SUBORDINATE_PREFIX.search(text)
        if subordinate and subordinate.start() < match.start():
            # The first recognized modal is in an unsupported subordinate clause.
            return None
        subject = text[: match.start()].strip(" ,:")
        tail = text[match.end():].strip(" ,:")
    if not subject or not tail:
        return None
    if modality == Modality.PROHIBIT and tail.lower().startswith(("not ", "never ", "only ")):
        # Includes double negation and additive "not only...but also...".
        return None
    if modality in {Modality.PERMIT, Modality.REQUIRE} and UNSUPPORTED_NEGATED_TAIL.match(tail):
        return None

    condition = _capture_tail(CONDITION, tail)
    exception = _capture_tail(EXCEPTION, tail)
    core = OBJECT_TRAIL.sub("", tail).strip(" .,:;")
    if UNSUPPORTED_PASSIVE.match(core):
        # Neither the actual actor nor its relation to the effect is known.
        return None
    if UNSUPPORTED_CAUSATIVE_HAVE.match(core):
        # "Have a service do X" is not an obligation, ban, or permission to
        # the action "have". The delegated effect needs explicit modeling.
        return None
    indirect = bool(INDIRECT_SCOPE.search(core))

    action, obj, delegated_actor = _extract_effect(core, indirect)
    if not action:
        return None

    span = SourceSpan(line_start=line, line_end=line, text=source_text)
    return Rule(
        rule_id=f"R{ordinal:04d}",
        modality=modality,
        subject=_norm_subject(subject),
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


def _norm_subject(value: str) -> str:
    value = _strip_markdown_wrappers(value)
    value = INLINE_SUBJECT_MARKUP.sub(lambda match: match.group("label"), value)
    return _norm_phrase(value)


def _strip_markdown_wrappers(value: str) -> str:
    value = value.strip()
    while True:
        for marker in ("**", "__", "*", "_", "`"):
            if value.startswith(marker) and value.endswith(marker) and len(value) > 2 * len(marker):
                value = value[len(marker):-len(marker)].strip()
                break
        else:
            break
    return value
