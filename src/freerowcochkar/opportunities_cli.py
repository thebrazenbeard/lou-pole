"""Separate bounded JSON-only CLI for advisory opportunity pathfinding."""

from __future__ import annotations

import argparse
import json
import sys

from .cli import IncompleteAnalysis, _read_source
from .opportunities import Action, OpportunityRequest, plan_opportunity


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def _fields(obj: object, allowed: set[str], required: set[str]) -> dict[str, object]:
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    if not required.issubset(obj) or set(obj) - allowed:
        raise ValueError("missing required or unrecognized JSON fields")
    return obj


def _names(obj: object) -> tuple[str, ...]:
    if type(obj) is not list or len(obj) > 64:
        raise ValueError("invalid identifier list")
    if any(not isinstance(name, str) or not 1 <= len(name) <= 128 for name in obj):
        raise ValueError("invalid identifier in list")
    return tuple(obj)


def _get_int(obj: object, label: str) -> int:
    if type(obj) is not int:
        raise ValueError(f"{label} must be an integer")
    return obj


def _action(obj: object) -> Action:
    fields = _fields(obj,
        {"id", "requires", "provides", "effects", "cost", "required_approvals", "provenance", "disabled"},
        {"id", "requires", "provides", "effects"})
    if not isinstance(fields["id"], str):
        raise ValueError("action id must be a string")
    provenance = fields.get("provenance", "caller_supplied_unverified")
    if not isinstance(provenance, str):
        raise ValueError("provenance must be a string")
    disabled = fields.get("disabled", False)
    if type(disabled) is not bool:
        raise ValueError("disabled must be a boolean")
    return Action(id=fields["id"], requires=_names(fields["requires"]),
                  provides=_names(fields["provides"]), effects=_names(fields["effects"]),
                  cost=_get_int(fields.get("cost", 0), "cost"),
                  required_approvals=_names(fields.get("required_approvals", [])),
                  provenance=provenance, disabled=disabled)


def _request(obj: object) -> OpportunityRequest:
    fields = _fields(obj, {"goal", "initial_capabilities", "actions", "allowed_effects",
                           "cost_ceiling", "granted_approvals", "failed_actions", "max_steps"},
                     {"goal", "initial_capabilities", "actions", "allowed_effects", "cost_ceiling"})
    if not isinstance(fields["goal"], str):
        raise ValueError("goal must be a string")
    actions = fields["actions"]
    if type(actions) is not list or len(actions) > 64:
        raise ValueError("invalid action list")
    return OpportunityRequest(
        goal=fields["goal"], initial_capabilities=_names(fields["initial_capabilities"]),
        actions=tuple(_action(item) for item in actions),
        allowed_effects=_names(fields["allowed_effects"]),
        cost_ceiling=_get_int(fields["cost_ceiling"], "cost_ceiling"),
        granted_approvals=_names(fields.get("granted_approvals", [])),
        failed_actions=_names(fields.get("failed_actions", [])),
        max_steps=_get_int(fields.get("max_steps", 16), "max_steps"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lou-pole-opportunities",
                                     description="Advisory route planning from caller-supplied JSON only.")
    parser.add_argument("path", nargs="?", default="-", help="Regular UTF-8 JSON file or '-' for stdin")
    args = parser.parse_args(argv)
    try:
        raw = _read_source(args.path)
        document = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys,
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))
        result = plan_opportunity(_request(document))
        print(json.dumps(result.to_dict(), sort_keys=True, ensure_ascii=True))
        return 0
    except (IncompleteAnalysis, OSError, ValueError, json.JSONDecodeError,
            RecursionError, OverflowError):
        # Never echo untrusted JSON, filesystem paths, credentials or raw values.
        print("INCOMPLETE_UNKNOWN: bounded opportunity planning not completed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
