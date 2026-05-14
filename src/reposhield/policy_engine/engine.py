"""Compatibility wrapper and PolicyGraph implementation."""
from __future__ import annotations

import os
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from ..contract import IntentMatcher
from ..models import (
    ActionIR,
    ContextGraph,
    ExecTrace,
    IntentDiff,
    PackageEvent,
    PolicyDecision,
    RepoAssetGraph,
    SecretTaintEvent,
    TaskContract,
    new_id,
)
from .compiler import PolicyRuleCompiler
from .context import PolicyEvalContext
from .decision_lattice import DecisionLattice
from .evaluator import RuleEvaluator
from .evidence_graph import PolicyEvaluationTrace
from .fact_extractor import FactExtractor
from .facts import PolicyFactSet
from .invariants import InvariantEngine
from .preflight_planner import PreflightPlan
from .rule_index import RuleIndex
from .rule_schema import RuleHit

VALID_MODES = {"policygraph-enforce"}
RISK_SCORE = {"low": 15, "medium": 40, "high": 70, "critical": 95}


class PolicyGraphEngine:
    policy_version = "reposhield-policygraph-v0.4"

    def __init__(self, domain_rules: list[dict[str, Any]] | None = None):
        self.matcher = IntentMatcher()
        self.extractor = FactExtractor()
        self.invariants = InvariantEngine()
        self.lattice = DecisionLattice()
        compiled = PolicyRuleCompiler().compile(domain_rules or self._load_domain_rules())
        self.rule_index = RuleIndex(compiled)
        self.evaluator = RuleEvaluator()

    def decide(self, ctx: PolicyEvalContext, *, mode: str = "policygraph-enforce") -> tuple[PolicyDecision, PolicyEvaluationTrace]:
        fact_set = self.extractor.extract(ctx)
        baseline = self._baseline_decision(ctx)
        invariant_hits = self.invariants.evaluate(fact_set)
        candidates, skipped = self.rule_index.candidates(fact_set)
        rule_hits = self.evaluator.evaluate(candidates, fact_set)
        hits = [*invariant_hits, *rule_hits]
        merged, lattice_path = self.lattice.merge(baseline, hits)
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
        return merged, trace

    def plan_preflight(self, decision: PolicyDecision) -> PreflightPlan:
        controls = set(decision.required_controls)
        required = bool(controls & {"sandbox_preflight", "package_preflight", "network_allowlist", "network_off", "human_approval"})
        run_even_if_blocked = os.environ.get("REPOSHIELD_PREFLIGHT_BLOCKED", "").lower() in {"1", "true", "full", "evidence"}
        if decision.decision == "sandbox_then_approval":
            required = True
        if decision.decision == "block" and run_even_if_blocked:
            required = True
        profile = "package_preflight" if "package_preflight" in controls else "network-off" if "network_off" in controls or "no_egress" in controls else "dry-run"
        evidence_mode = "full" if run_even_if_blocked else "summary"
        return PreflightPlan(required=required, profile=profile, evidence_mode=evidence_mode, run_even_if_blocked=run_even_if_blocked, decision_phase="pre_decide", reason_codes=decision.reason_codes, required_controls=decision.required_controls)

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

    def _baseline_decision(self, ctx: PolicyEvalContext) -> PolicyDecision:
        action = ctx.action
        intent = self.matcher.match(ctx.contract, action)
        reasons: list[str] = []
        controls: list[str] = []
        score = RISK_SCORE[action.risk]

        if ctx.context_graph.has_untrusted(action.source_ids):
            reasons.append("influenced_by_untrusted_source")
            score += 12
        if intent.contract_match in {"violation", "unknown"}:
            reasons.extend(intent.violation_reason or ["contract_violation"])
            score += 15
        elif intent.contract_match == "partial_match":
            reasons.extend(intent.violation_reason)
            score += 8
        if ctx.package_event:
            reasons.extend(ctx.package_event.reason_codes)
            if ctx.package_event.lifecycle_scripts:
                reasons.append("package_lifecycle_script_possible")
                controls.extend(["no_lifecycle_script", "secret_mount_masked"])
            if ctx.package_event.source in {"git_url", "tarball_url"}:
                controls.append("package_preflight")
                score += 15
            if ctx.package_event.risk == "critical":
                score += 10
        if ctx.secret_event:
            reasons.append(ctx.secret_event.event)
            controls.append("no_egress")
            score += 20
        if ctx.exec_trace:
            if ctx.exec_trace.network_attempts:
                reasons.append("sandbox_network_egress_attempt")
                score += 15
            if ctx.exec_trace.package_scripts:
                reasons.append("sandbox_lifecycle_observed")
            if "secret_access" in ctx.exec_trace.risk_observed:
                reasons.append("sandbox_secret_access_observed")
                score += 20
        if action.metadata.get("memory_authorization_denied"):
            reasons.append("memory_authorization_denied")
            controls.append("memory_taint_gate")
            score += 20
        return self._decision(action, "allow", min(score, 100), reasons, controls, "PolicyGraph baseline; domain rules and invariants determine the final decision.", intent, ctx.package_event, ctx.exec_trace)

    def _decision(self, action: ActionIR, decision: str, score: int, reasons: list[str], controls: list[str], explanation: str, intent: IntentDiff | None, package_event: PackageEvent | None, exec_trace: ExecTrace | None) -> PolicyDecision:
        dedup_reasons = list(dict.fromkeys(reasons))
        dedup_controls = list(dict.fromkeys(controls))
        evidence_refs = [*action.source_ids]
        if package_event:
            evidence_refs.append(package_event.package_event_id)
        if exec_trace:
            evidence_refs.append(exec_trace.exec_trace_id)
        return PolicyDecision(
            decision_id=new_id("dec"),
            action_id=action.action_id,
            decision=decision,  # type: ignore[arg-type]
            risk_score=score,
            reason_codes=dedup_reasons,
            required_controls=dedup_controls,
            explanation=explanation,
            intent_diff=intent,
            package_event_id=package_event.package_event_id if package_event else None,
            exec_trace_id=exec_trace.exec_trace_id if exec_trace else None,
            matched_rules=[],
            evidence_refs=list(dict.fromkeys(evidence_refs)),
            policy_version=self.policy_version,
            rule_trace=[
                {
                    "engine": "policygraph",
                    "stage": "baseline",
                    "semantic_action": action.semantic_action,
                    "risk": action.risk,
                    "source_ids": action.source_ids,
                    "reason_codes": dedup_reasons,
                    "decision": decision,
                }
            ],
        )

    @staticmethod
    def _explanation(decision: PolicyDecision, hits: list[RuleHit]) -> str:
        invariant_ids = [hit.rule_id for hit in hits if hit.invariant]
        if invariant_ids:
            return f"PolicyGraph invariant(s) {', '.join(invariant_ids)} produced a non-downgradable {decision.decision} decision."
        return decision.explanation

    @staticmethod
    def _load_domain_rules() -> list[dict[str, Any]]:
        pack = os.environ.get("REPOSHIELD_POLICY_PACK")
        path = Path(pack) if pack else Path(__file__).with_name("policies") / "core_coding_agent.yaml"
        data = _load_policy_yaml(path)
        rules = data.get("rules", []) if isinstance(data, dict) else []
        if not isinstance(rules, list):
            raise ValueError(f"policy pack rules must be a list: {path}")
        return [dict(rule) for rule in rules]

class PolicyEngine:
    """Backward-compatible PolicyEngine entrypoint backed only by PolicyGraph."""

    def __init__(self, mode: str | None = None) -> None:
        self.mode = mode or os.environ.get("REPOSHIELD_POLICY_ENGINE", "policygraph-enforce")
        if self.mode not in VALID_MODES:
            self.mode = "policygraph-enforce"
        self.policygraph = PolicyGraphEngine()
        self._eval_events: list[dict[str, Any]] = []
        self._fact_events: list[dict[str, Any]] = []

    @property
    def policy_version(self) -> str:
        return self.policygraph.policy_version

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
        ctx = PolicyEvalContext(contract, action, asset_graph, context_graph, package_event, secret_event, exec_trace, "post_decide" if exec_trace else "pre_decide")
        graph_decision, trace = self.policygraph.decide(ctx, mode=self.mode)
        event = trace.to_dict()
        self._eval_events.append(event)
        self._fact_events.append({
            "fact_set_id": trace.fact_set_id,
            "fact_hash": trace.fact_hash,
            "fact_count": len(trace.fact_nodes),
            "namespace_counts": _fact_namespace_counts(trace.fact_nodes),
            "summary": _fact_summary(trace.fact_nodes),
            "policy_eval_trace_id": trace.policy_eval_trace_id,
        })
        return graph_decision

    def plan_preflight(self, decision: PolicyDecision) -> PreflightPlan:
        return self.policygraph.plan_preflight(decision)

    def consume_eval_events(self) -> list[dict[str, Any]]:
        events = self._eval_events
        self._eval_events = []
        return events

    def consume_fact_events(self) -> list[dict[str, Any]]:
        events = self._fact_events
        self._fact_events = []
        return events


def _load_policy_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for PolicyGraph YAML policy packs") from exc


def _fact_namespace_counts(nodes: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in nodes:
        namespace = str(node.get("namespace") or "unknown")
        counts[namespace] = counts.get(namespace, 0) + 1
    return counts


def _fact_summary(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    important = {"action", "source", "asset", "contract", "package", "secret", "mcp", "memory", "sandbox"}
    out = []
    for node in nodes:
        if node.get("namespace") in important:
            out.append({k: node.get(k) for k in ("fact_id", "namespace", "key", "value", "evidence_refs")})
        if len(out) >= 40:
            break
    return out
