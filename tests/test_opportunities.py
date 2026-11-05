"""The opportunity planner suggests routes; it never performs their actions."""

import unittest

from freerowcochkar.opportunities import Action, OpportunityRequest, RouteStatus, plan_opportunity


class OpportunityPlannerTests(unittest.TestCase):
    def request(self, *, goal="desktop_view", actions=(), initial=("source",), **extra):
        return OpportunityRequest(
            goal=goal,
            initial_capabilities=initial,
            actions=tuple(actions),
            allowed_effects=("local_browser", "private_authenticated_network", "local_workspace"),
            cost_ceiling=0,
            **extra,
        )

    def test_failed_cloud_browser_loopback_reroutes_same_environment(self):
        request = self.request(
            actions=(
                Action(id="cloud_browser_localhost", requires=("source",), provides=("desktop_view",), effects=("local_browser",)),
                Action(id="same_environment_browser", requires=("source",), provides=("desktop_view",), effects=("local_browser",)),
            ),
            failed_actions=("cloud_browser_localhost",),
        )
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.AVAILABLE)
        self.assertEqual(result.action_ids, ("same_environment_browser",))
        self.assertFalse(result.executed)
        self.assertFalse(result.verified)

    def test_static_preview_does_not_silently_grant_approval(self):
        request = self.request(actions=(Action(
            id="publish_static_preview", requires=("source",), provides=("desktop_view",),
            effects=("local_workspace",), required_approvals=("preview_publication",),
        ),))
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.NEEDS_APPROVAL)
        self.assertEqual(result.missing_approvals, ("preview_publication",))
        self.assertFalse(result.executed)

    def test_zero_budget_excludes_paid_route_and_finds_free_multistep(self):
        request = self.request(actions=(
            Action(id="paid_relay", requires=("source",), provides=("desktop_view",), cost=1, effects=("local_workspace",)),
            Action(id="prepare_local", requires=("source",), provides=("ready",), effects=("local_workspace",)),
            Action(id="open_local", requires=("ready",), provides=("desktop_view",), effects=("local_browser",)),
        ))
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.AVAILABLE)
        self.assertEqual(result.action_ids, ("prepare_local", "open_local"))
        self.assertEqual(result.total_cost, 0)

    def test_public_unauthenticated_rfb_excluded_for_private_authenticated(self):
        request = self.request(actions=(
            Action(id="open_public_unauth_rfb", requires=("source",), provides=("desktop_view",), effects=("public_unauthenticated_network",)),
            Action(id="private_authenticated_rfb", requires=("source",), provides=("desktop_view",), effects=("private_authenticated_network",)),
        ))
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.AVAILABLE)
        self.assertEqual(result.action_ids, ("private_authenticated_rfb",))

    def test_no_route_honest_and_reports_blockers(self):
        request = self.request(actions=(
            Action(id="only_paid_route", requires=("source",), provides=("desktop_view",), cost=2, effects=("local_workspace",)),
        ))
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.NO_ROUTE)
        self.assertEqual(result.action_ids, ())
        self.assertIn("COST_CEILING", result.blockers)
        self.assertFalse(result.executed)

    def test_cycle_and_repeated_states_terminate(self):
        request = self.request(goal="unreachable", actions=(
            Action(id="a_to_b", requires=("a",), provides=("b",), effects=("local_workspace",)),
            Action(id="b_to_a", requires=("b",), provides=("a",), effects=("local_workspace",)),
            Action(id="noop", requires=("a",), provides=("a",), effects=("local_workspace",)),
        ), initial=("a",))
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.NO_ROUTE)
        self.assertLessEqual(result.explored_states, 4)
        self.assertFalse(result.executed)

    def test_approved_path_beats_cheaper_pending_path(self):
        request = self.request(actions=(
            Action(id="pending_shortcut", requires=("source",), provides=("desktop_view",),
                   effects=("local_workspace",), required_approvals=("approval",)),
            Action(id="ready", requires=("source",), provides=("ready",), effects=("local_workspace",)),
            Action(id="view", requires=("ready",), provides=("desktop_view",), effects=("local_workspace",)),
        ))
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.AVAILABLE)
        self.assertEqual(result.action_ids, ("ready", "view"))
        self.assertEqual(result.missing_approvals, ())

    def test_disabled_route_does_not_become_available(self):
        request = self.request(actions=(
            Action(id="disabled", requires=("source",), provides=("desktop_view",),
                   effects=("local_workspace",), disabled=True),
        ))
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.NO_ROUTE)
        self.assertIn("DISABLED_ACTION", result.blockers)

    def test_unstated_effect_never_implies_authorization(self):
        request = self.request(actions=(
            Action(id="unknown_effect", requires=("source",), provides=("desktop_view",), effects=()),
        ))
        result = plan_opportunity(request)
        self.assertEqual(result.status, RouteStatus.NO_ROUTE)
        self.assertIn("EFFECT_NOT_ALLOWED", result.blockers)

    def test_search_exhaustion_is_unknown_not_definitive_no_route(self):
        # Independent capabilities create >4096 reachable subsets, exceeding
        # the bounded planner's search budget before exhaustion is proved.
        actions = tuple(Action(id=f"discover_{i}", requires=("source",),
                               provides=(f"found_{i}",), effects=("local_workspace",))
                        for i in range(15))
        result = plan_opportunity(self.request(goal="unreachable", actions=actions))
        self.assertEqual(result.status.value, "INCOMPLETE_UNKNOWN")
        self.assertIn("BOUNDED_SEARCH_LIMIT", result.blockers)
        self.assertFalse(result.executed)

    def test_capability_state_cap_is_unknown_not_no_route(self):
        actions = []
        required = "source"
        for step in range(8):
            capabilities = tuple(f"cap_{step}_{i}" for i in range(64))
            actions.append(Action(id=f"step_{step}", requires=(required,),
                                  provides=capabilities, effects=("local_workspace",)))
            required = capabilities[-1]
        actions.append(Action(id="finish", requires=(required,),
                              provides=("desktop_view",), effects=("local_workspace",)))
        result = plan_opportunity(self.request(actions=actions))
        self.assertEqual(result.status.value, "INCOMPLETE_UNKNOWN")
        self.assertIn("BOUNDED_SEARCH_LIMIT", result.blockers)

    def test_incomplete_approved_search_cannot_certify_approval_required(self):
        all_bits = tuple(f"bit_{i}" for i in range(15))
        actions = tuple(Action(id=f"seed_{i}", requires=("source",),
                               provides=(bit,), effects=("local_workspace",))
                        for i, bit in enumerate(all_bits)) + (
            Action(id="approved_finish", requires=all_bits, provides=("desktop_view",),
                   effects=("local_workspace",)),
            Action(id="pending_shortcut", requires=("source",), provides=("desktop_view",),
                   effects=("local_workspace",), required_approvals=("external_approval",)),
        )
        result = plan_opportunity(self.request(actions=actions, max_steps=16))
        self.assertEqual(result.status.value, "INCOMPLETE_UNKNOWN")
        self.assertIn("BOUNDED_SEARCH_LIMIT", result.blockers)
        self.assertFalse(result.executed)

    def test_direct_api_rejects_scalar_strings_for_tuple_fields(self):
        with self.assertRaises(ValueError):
            plan_opportunity(OpportunityRequest(
                goal="route", initial_capabilities="router", actions=(),
                allowed_effects=(), cost_ceiling=0))
        with self.assertRaises(ValueError):
            plan_opportunity(self.request(actions=(Action(
                id="bad_requires", requires="source", provides=("desktop_view",),
                effects=("local_workspace",)),)))
        with self.assertRaises(ValueError):
            plan_opportunity(self.request(actions=(Action(
                id="bad_effects", requires=("source",), provides=("desktop_view",),
                effects="local_workspace"),)))


if __name__ == "__main__":
    unittest.main()
