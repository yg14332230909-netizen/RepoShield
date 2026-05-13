"""Compatibility wrapper and PolicyGraph implementation."""
from __future__ import annotations

import os
from dataclasses import asdict, replace
from typing import Any

from ..models import (
    ActionIR,
    ContextGraph,
    ExecTrace,
    PackageEvent,
    PolicyDecision,
    RepoAssetGraph,
    SecretTaintEvent,
    TaskContract,
)
from .compiler import PolicyRuleCompiler
from .context import PolicyEvalContext
from .decision_lattice import DecisionLattice
from .evaluator import RuleEvaluator
from .evidence_graph import PolicyEvaluationTrace
from .fact_extractor import FactExtractor
from .facts import PolicyFactSet
from .invariants import InvariantEngine
from .legacy import LegacyPolicyEngine
from .preflight_planner import PreflightPlan
from .rule_index import RuleIndex
from .rule_schema import RuleHit

VALID_MODES = {"legacy", "policygraph-shadow", "policygraph-enforce"}


class PolicyGraphEngine:
    policy_version = "reposhield-policygraph-v0.4"

    def __init__(self, domain_rules: list[dict[str, Any]] | None = None):
        self.legacy = LegacyPolicyEngine()
        self.extractor = FactExtractor()
        self.invariants = InvariantEngine()
        self.lattice = DecisionLattice()
        compiled = PolicyRuleCompiler().compile(domain_rules or self._default_domain_rules())
        self.rule_index = RuleIndex(compiled)
        self.evaluator = RuleEvaluator()

    def decide(self, ctx: PolicyEvalContext, *, mode: str = "policygraph-enforce") -> tuple[PolicyDecision, PolicyEvaluationTrace, PolicyDecision]:
        legacy = self.legacy.decide(ctx.contract, ctx.action, ctx.asset_graph, ctx.context_graph, ctx.package_event, ctx.secret_event, ctx.exec_trace)
        fact_set = self.extractor.extract(ctx)
        invariant_hits = self.invariants.evaluate(fact_set)
        candidates, skipped = self.rule_index.candidates(fact_set)
        rule_hits = self.evaluator.evaluate(candidates, fact_set)
        hits = [*invariant_hits, *rule_hits]
        merged, lattice_path = self.lattice.merge(legacy, hits)
        trace = PolicyEvaluationTrace.build(
            action_id=ctx.action.action_id,
            engine_mode=mode,
            policy_version=self.policy_version,
            fact_set=fact_set,
            final_decision=merged.decision,
            hits=hits,
            lattice_path=lattice_path,
            skipped_rules_summary=skipped,
        )
        merged = self._decorate_decision(merged, fact_set, hits, trace, lattice_path, skipped)
        return merged, trace, legacy

    def plan_preflight(self, decision: PolicyDecision) -> PreflightPlan:
        controls = set(decision.required_controls)
        required = bool(controls & {"sandbox_preflight", "package_preflight", "network_allowlist", "network_off", "human_approval"}) or decision.decision in {"sandbox_then_approval", "block"}
        profile = "network-off" if "network_off" in controls or "no_egress" in controls else "dry-run"
        return PreflightPlan(required=required, profile=profile, evidence_mode="summary", reason_codes=decision.reason_codes, required_controls=decision.required_controls)

    def _decorate_decision(
        self,
        decision: PolicyDecision,
        fact_set: PolicyFactSet,
        hits: list[RuleHit],
        trace: PolicyEvaluationTrace,
        lattice_path: list[dict[str, Any]],
        skipped: dict[str, Any],
    ) -> PolicyDecision:
        touched_asset_types = sorted({str(v) for v in fact_set.values("asset", "touched_type") if v})
        source_floor = next(iter(fact_set.values("source", "trust_floor")), None)
        preflight = asdict(self.plan_preflight(decision))
        graph_trace = {
            "engine": "policygraph",
            "policy_eval_trace_id": trace.policy_eval_trace_id,
            "fact_set_id": fact_set.fact_set_id,
            "fact_hash": fact_set.content_hash,
            "fact_count": len(fact_set.facts),
            "rule_hit_count": len(hits),
            "invariant_hits": [hit.rule_id for hit in hits if hit.invariant],
            "decision_lattice_path": lattice_path,
            "skipped_rules_summary": skipped,
            "source_trust_floor": source_floor,
            "touched_asset_types": touched_asset_types,
            "preflight_plan": preflight,
        }
        return replace(
            decision,
            policy_version=self.policy_version,
            evidence_refs=list(dict.fromkeys([*decision.evidence_refs, fact_set.fact_set_id, trace.policy_eval_trace_id])),
            rule_trace=[*decision.rule_trace, graph_trace],
            explanation=self._explanation(decision, hits),
        )

    @staticmethod
    def _explanation(decision: PolicyDecision, hits: list[RuleHit]) -> str:
        invariant_ids = [hit.rule_id for hit in hits if hit.invariant]
        if invariant_ids:
            return f"PolicyGraph invariant(s) {', '.join(invariant_ids)} produced a non-downgradable {decision.decision} decision."
        return decision.explanation

    @staticmethod
    def _default_domain_rules() -> list[dict[str, Any]]:
        return [
            {
                "rule_id": "DSL-SANDBOX-UNKNOWN-001",
                "name": "unknown_side_effect_requires_preflight",
                "category": "parser",
                "match": {"action.semantic_action": "unknown_side_effect"},
                "decision": "sandbox_then_approval",
                "risk_score": 82,
                "reason_codes": ["default_fail_closed"],
                "required_controls": ["sandbox_preflight", "human_approval"],
            }
        ]


class PolicyEngine:
    """Backward-compatible PolicyEngine entrypoint with feature-flagged modes."""

    def __init__(self, mode: str | None = None) -> None:
        self.mode = mode or os.environ.get("REPOSHIELD_POLICY_ENGINE", "policygraph-enforce")
        if self.mode not in VALID_MODES:
            self.mode = "policygraph-enforce"
        self.legacy = LegacyPolicyEngine()
        self.policygraph = PolicyGraphEngine()
        self._eval_events: list[dict[str, Any]] = []

    @property
    def policy_version(self) -> str:
        return self.legacy.policy_version if self.mode == "legacy" else self.policygraph.policy_version

    def decide(
        self,
        contract: TaskContract,
        action: ActionIR,
        asset_graph: RepoAssetGraph,
        context_graph: ContextGraph,
        package_event: PackageEvent | None = None,
        secret_event: SecretTaintEvent | None = None,
        exec_trace: ExecTrace | None = None,
    ) -> PolicyDecision:
        if self.mode == "legacy":
            return self.legacy.decide(contract, action, asset_graph, context_graph, package_event, secret_event, exec_trace)

        ctx = PolicyEvalContext(contract, action, asset_graph, context_graph, package_event, secret_event, exec_trace, "post_decide" if exec_trace else "pre_decide")
        graph_decision, trace, legacy_decision = self.policygraph.decide(ctx, mode=self.mode)
        event = trace.to_dict()
        event["shadow_diff"] = self._shadow_diff(legacy_decision, graph_decision)
        self._eval_events.append(event)

        if self.mode == "policygraph-shadow":
            shadow_trace = {
                "engine": "policygraph-shadow",
                "policy_eval_trace_id": trace.policy_eval_trace_id,
                "shadow_decision": graph_decision.decision,
                "shadow_risk_score": graph_decision.risk_score,
                "shadow_diff": event["shadow_diff"],
            }
            return replace(
                legacy_decision,
                evidence_refs=list(dict.fromkeys([*legacy_decision.evidence_refs, trace.fact_set_id, trace.policy_eval_trace_id])),
                rule_trace=[*legacy_decision.rule_trace, shadow_trace],
            )
        return graph_decision

    def consume_eval_events(self) -> list[dict[str, Any]]:
        events = self._eval_events
        self._eval_events = []
        return events

    @staticmethod
    def _shadow_diff(legacy: PolicyDecision, graph: PolicyDecision) -> dict[str, Any]:
        if legacy.decision == graph.decision and legacy.reason_codes == graph.reason_codes:
            kind = "same_decision"
        elif legacy.decision == graph.decision:
            kind = "reason_changed"
        elif graph.decision == "block" and legacy.decision != "block":
            kind = "new_block"
        elif legacy.decision == "block" and graph.decision != "block":
            kind = "new_allow"
        else:
            kind = "decision_changed"
        return {
            "kind": kind,
            "legacy_decision": legacy.decision,
            "policygraph_decision": graph.decision,
            "legacy_reasons": legacy.reason_codes,
            "policygraph_reasons": graph.reason_codes,
        }
