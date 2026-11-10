"""Advisory opportunity routes over caller-supplied, unverified capabilities."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from heapq import heappop, heappush


MAX_ACTIONS = 64
MAX_STATES = 4096
MAX_QUEUE = 8192
MAX_CAPABILITIES = 512
MAX_STEPS = 32


class RouteStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    NO_ROUTE = "NO_ROUTE"
    INCOMPLETE_UNKNOWN = "INCOMPLETE_UNKNOWN"


@dataclass(frozen=True)
class Action:
    id: str
    requires: tuple[str, ...]
    provides: tuple[str, ...]
    effects: tuple[str, ...]
    cost: int = 0
    required_approvals: tuple[str, ...] = ()
    provenance: str = "caller_supplied_unverified"
    disabled: bool = False


@dataclass(frozen=True)
class OpportunityRequest:
    goal: str
    initial_capabilities: tuple[str, ...]
    actions: tuple[Action, ...]
    allowed_effects: tuple[str, ...]
    cost_ceiling: int = 0
    granted_approvals: tuple[str, ...] = ()
    failed_actions: tuple[str, ...] = ()
    max_steps: int = 16


@dataclass(frozen=True)
class RoutePlan:
    status: RouteStatus
    action_ids: tuple[str, ...] = ()
    total_cost: int | None = None
    missing_approvals: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    explored_states: int = 0
    executed: bool = False
    verified: bool = False
    provenance: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "action_ids": list(self.action_ids),
            "total_cost": self.total_cost,
            "missing_approvals": list(self.missing_approvals),
            "blockers": list(self.blockers),
            "explored_states": self.explored_states,
            "executed": False,
            "verified": False,
            "evidence_class": "CALLER_SUPPLIED_UNVERIFIED",
            "provenance": {action_id: ref for action_id, ref in self.provenance},
        }


def plan_opportunity(request: OpportunityRequest) -> RoutePlan:
    """Find advisory paths using only the caller's asserted capability/action graph.

    AVAILABLE means no *declared* approval remains outstanding, never an
    independently verified permission or executed external effect. Actions
    without an explicitly allowed effect are ineligible. A route requiring
    pending approval is returned only if no entirely approved route exists.
    """
    _validate_request(request)
    if request.goal in request.initial_capabilities:
        return RoutePlan(status=RouteStatus.AVAILABLE, total_cost=0, explored_states=1)

    allowed = set(request.allowed_effects)
    failed = set(request.failed_actions)
    grants = set(request.granted_approvals)
    blockers: set[str] = set()
    eligible: list[Action] = []
    for action in sorted(request.actions, key=lambda item: item.id):
        if action.disabled:
            blockers.add("DISABLED_ACTION")
        elif action.id in failed:
            blockers.add("FAILED_ACTION")
        elif not action.effects or not set(action.effects).issubset(allowed):
            blockers.add("EFFECT_NOT_ALLOWED")
        elif action.cost > request.cost_ceiling:
            blockers.add("COST_CEILING")
        else:
            eligible.append(action)

    approved, first_explored, first_limited = _search(request, eligible, grants, include_pending=False)
    if approved is not None:
        return _plan(RouteStatus.AVAILABLE, approved, first_explored, request.actions)

    pending, second_explored, second_limited = _search(request, eligible, grants, include_pending=True)
    if pending is not None:
        candidate = _plan(RouteStatus.NEEDS_APPROVAL, pending,
                          first_explored + second_explored, request.actions)
        if first_limited:
            # An approved route may have been pruned by the search budget;
            # cannot certify that the pending approval is actually necessary.
            return replace(candidate, status=RouteStatus.INCOMPLETE_UNKNOWN,
                           blockers=("BOUNDED_SEARCH_LIMIT",))
        return candidate

    limited = first_limited or second_limited
    if limited:
        blockers.add("BOUNDED_SEARCH_LIMIT")
    if not eligible and not blockers:
        blockers.add("NO_ACTIONS")
    if eligible and not blockers:
        blockers.add("UNMET_PRECONDITIONS_OR_NO_PATH")
    return RoutePlan(status=RouteStatus.INCOMPLETE_UNKNOWN if limited else RouteStatus.NO_ROUTE,
                     blockers=tuple(sorted(blockers)),
                     explored_states=first_explored + second_explored)


def _plan(status: RouteStatus, found: tuple, explored: int,
          actions: tuple[Action, ...]) -> RoutePlan:
    cost, route, approvals = found
    lookup = {action.id: action for action in actions}
    return RoutePlan(status=status, action_ids=route, total_cost=cost,
                     missing_approvals=tuple(sorted(approvals)), explored_states=explored,
                     provenance=tuple((name, lookup[name].provenance) for name in route))


def _search(request: OpportunityRequest, actions: list[Action], grants: set[str],
            *, include_pending: bool) -> tuple[tuple | None, int, bool]:
    start = frozenset(request.initial_capabilities)
    # Monotone capabilities make all no-op/cyclic transitions unnecessary.
    # Heap rank: zero-approval (separate pass), total cost, steps, route IDs.
    queue: list[tuple[int, int, tuple[str, ...], frozenset[str], frozenset[str]]] = []
    heappush(queue, (0, 0, (), start, frozenset()))
    seen: dict[tuple[frozenset[str], frozenset[str]], tuple[int, int, tuple[str, ...]]] = {}
    explored = 0
    hit_step_limit = False
    hit_queue_limit = False
    hit_capability_limit = False
    while queue and explored < MAX_STATES:
        cost, steps, route, capabilities, approvals = heappop(queue)
        key = (capabilities, approvals)
        rank = (cost, steps, route)
        previous = seen.get(key)
        if previous is not None and previous <= rank:
            continue
        seen[key] = rank
        explored += 1
        if request.goal in capabilities:
            return (cost, route, approvals), explored, False
        if steps >= request.max_steps:
            hit_step_limit = True
            continue
        for action in actions:
            if not set(action.requires).issubset(capabilities):
                continue
            added = set(action.provides) - capabilities
            if not added:
                continue
            next_cost = cost + action.cost
            if next_cost > request.cost_ceiling:
                continue
            missing = set(action.required_approvals) - grants
            if missing and not include_pending:
                continue
            next_approvals = approvals.union(missing)
            next_capabilities = capabilities.union(added)
            if len(next_capabilities) > MAX_CAPABILITIES:
                hit_capability_limit = True
                continue
            next_route = route + (action.id,)
            new_key = (next_capabilities, next_approvals)
            new_rank = (next_cost, steps + 1, next_route)
            prior = seen.get(new_key)
            if prior is None or new_rank < prior:
                if len(queue) >= MAX_QUEUE:
                    hit_queue_limit = True
                    continue
                heappush(queue, (next_cost, steps + 1, next_route,
                                 next_capabilities, next_approvals))
    return None, explored, bool(queue) or hit_step_limit or hit_queue_limit or hit_capability_limit


def _validate_request(request: OpportunityRequest) -> None:
    if not isinstance(request, OpportunityRequest):
        raise ValueError("expected an OpportunityRequest")
    if type(request.cost_ceiling) is not int or not 0 <= request.cost_ceiling <= 10**9:
        raise ValueError("cost_ceiling must be a nonnegative bounded integer")
    if type(request.max_steps) is not int or not 1 <= request.max_steps <= MAX_STEPS:
        raise ValueError("max_steps must be between 1 and 32")
    if type(request.actions) is not tuple:
        raise ValueError("actions must be a tuple of Action records")
    if len(request.actions) > MAX_ACTIONS:
        raise ValueError("too many actions")
    _check_names((request.goal,))
    for names in (request.initial_capabilities, request.allowed_effects,
                  request.granted_approvals, request.failed_actions):
        _check_names(names)
    if len(request.initial_capabilities) > MAX_CAPABILITIES:
        raise ValueError("too many initial capabilities")
    ids: set[str] = set()
    for action in request.actions:
        if not isinstance(action, Action):
            raise ValueError("expected typed Action records")
        _check_names((action.id,))
        if action.id in ids:
            raise ValueError("action identifiers must be unique")
        ids.add(action.id)
        for names in (action.requires, action.provides, action.effects,
                      action.required_approvals):
            _check_names(names)
        if not action.provides:
            raise ValueError("actions must provide at least one capability")
        if type(action.cost) is not int or not 0 <= action.cost <= 10**9:
            raise ValueError("action cost must be a nonnegative bounded integer")
        if type(action.disabled) is not bool:
            raise ValueError("action.disabled must be boolean")
        if not isinstance(action.provenance, str) or len(action.provenance) > 512:
            raise ValueError("invalid provenance reference")


def _check_names(names: tuple[str, ...]) -> None:
    if type(names) is not tuple or len(names) > 64 or any(not isinstance(name, str) or
                             not 1 <= len(name) <= 128 or any(ord(ch) < 32 for ch in name)
                             for name in names):
        raise ValueError("invalid or oversized identifier list")
