"""Compatibility wrapper and PolicyGraph implementation."""
from __future__ import annotations

import os
from dataclasses import asdict, replace
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
        compiled = PolicyRuleCompiler().compile(domain_rules or self._default_domain_rules())
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
    def _default_domain_rules() -> list[dict[str, Any]]:
        return [
            {
                "rule_id": "RS-SECRET-001",
                "name": "secret_read_hard_deny",
                "category": "secret",
                "match": {"action.semantic_action": "read_secret_file"},
                "decision": "block",
                "risk_score": 100,
                "reason_codes": ["hard_deny_read_secret"],
                "required_controls": ["block"],
            },
            {
                "rule_id": "RS-EGRESS-001",
                "name": "secret_tainted_network_hard_deny",
                "category": "egress",
                "match": {"action.semantic_action": "send_network_request", "secret.event_any": ["egress_after_secret", "token_like_value_in_tool_args"]},
                "decision": "block",
                "risk_score": 100,
                "reason_codes": ["hard_deny_secret_egress"],
                "required_controls": ["block", "no_egress"],
            },
            {
                "rule_id": "RS-MEM-001",
                "name": "memory_denied_high_risk_action",
                "category": "memory",
                "match": {"memory.authorization_denied": True, "action.high_risk": True},
                "decision": "block",
                "risk_score": 90,
                "reason_codes": ["memory_authorization_denied"],
                "required_controls": ["memory_taint_gate", "block"],
            },
            {
                "rule_id": "RS-RELEASE-001",
                "name": "release_or_force_push_requires_double_approval",
                "category": "release",
                "match": {"action.semantic_any": ["publish_artifact", "git_push_force"]},
                "decision": "block",
                "risk_score": 95,
                "reason_codes": ["requires_double_approval"],
                "required_controls": ["block", "double_approval", "dry_run_only"],
            },
            {
                "rule_id": "RS-REGISTRY-001",
                "name": "registry_config_change_blocked",
                "category": "registry",
                "match": {"action.semantic_action": "modify_registry_config"},
                "decision": "block",
                "risk_score": 92,
                "reason_codes": ["registry_config_change"],
                "required_controls": ["block_or_admin_approval"],
            },
            {
                "rule_id": "RS-CI-001",
                "name": "untrusted_source_cannot_modify_ci",
                "category": "ci",
                "match": {"action.semantic_action": "modify_ci_pipeline", "source.has_untrusted": True},
                "decision": "block",
                "risk_score": 92,
                "reason_codes": ["untrusted_source_cannot_modify_ci"],
                "required_controls": ["block_or_human_approval"],
            },
            {
                "rule_id": "RS-SC-001",
                "name": "untrusted_remote_dependency_install",
                "category": "supply_chain",
                "match": {"action.semantic_any": ["install_git_dependency", "install_tarball_dependency"], "source.has_untrusted": True},
                "decision": "block",
                "risk_score": 95,
                "reason_codes": ["untrusted_source_cannot_authorize_dependency_install"],
                "required_controls": ["block", "package_preflight"],
            },
            {
                "rule_id": "RS-SC-002",
                "name": "contract_mismatch_remote_dependency_install",
                "category": "supply_chain",
                "match": {"action.semantic_any": ["install_git_dependency", "install_tarball_dependency"], "contract.match_any": ["violation", "unknown"]},
                "decision": "block",
                "risk_score": 95,
                "reason_codes": ["untrusted_source_cannot_authorize_dependency_install"],
                "required_controls": ["block", "package_preflight"],
            },
            {
                "rule_id": "RS-SC-003",
                "name": "remote_dependency_requires_preflight",
                "category": "supply_chain",
                "match": {"action.semantic_any": ["install_git_dependency", "install_tarball_dependency"]},
                "decision": "sandbox_then_approval",
                "risk_score": 87,
                "reason_codes": [],
                "required_controls": ["package_preflight", "network_off", "human_approval"],
            },
            {
                "rule_id": "RS-SC-004",
                "name": "registry_install_requires_preflight",
                "category": "supply_chain",
                "match": {"action.semantic_action": "install_registry_dependency"},
                "decision": "sandbox_then_approval",
                "risk_score": 78,
                "reason_codes": [],
                "required_controls": ["package_preflight", "network_allowlist", "secret_mount_masked", "human_approval"],
            },
            {
                "rule_id": "RS-NET-001",
                "name": "untrusted_source_cannot_authorize_network",
                "category": "egress",
                "match": {"action.semantic_action": "send_network_request", "source.has_untrusted": True},
                "decision": "block",
                "risk_score": 90,
                "reason_codes": ["untrusted_source_cannot_authorize_network"],
                "required_controls": ["block", "no_egress"],
            },
            {
                "rule_id": "RS-NET-002",
                "name": "trusted_network_requires_approval",
                "category": "egress",
                "match": {"action.semantic_action": "send_network_request"},
                "decision": "sandbox_then_approval",
                "risk_score": 78,
                "reason_codes": [],
                "required_controls": ["network_allowlist", "human_approval"],
            },
            {
                "rule_id": "RS-MCP-001",
                "name": "destructive_mcp_tool_blocked",
                "category": "mcp",
                "match": {"action.semantic_action": "invoke_destructive_mcp_tool"},
                "decision": "block",
                "risk_score": 90,
                "reason_codes": ["destructive_mcp_tool"],
                "required_controls": ["mcp_proxy", "human_approval"],
            },
            {
                "rule_id": "RS-MCP-002",
                "name": "mcp_proxy_blocked_invocation",
                "category": "mcp",
                "match": {"action.semantic_action": "invoke_mcp_tool", "mcp.decision": "blocked"},
                "decision": "block",
                "risk_score": 88,
                "reason_codes": ["mcp_proxy_blocked"],
                "required_controls": ["mcp_proxy"],
            },
            {
                "rule_id": "RS-MEM-002",
                "name": "tainted_memory_write_is_sandboxed",
                "category": "memory",
                "match": {"action.semantic_action": "memory_write", "source.has_untrusted": True},
                "decision": "allow_in_sandbox",
                "risk_score": 60,
                "reason_codes": ["tainted_memory_write"],
                "required_controls": ["memory_taint", "ttl"],
            },
            {
                "rule_id": "RS-MEM-003",
                "name": "trusted_memory_write_allowed_with_ttl",
                "category": "memory",
                "match": {"action.semantic_action": "memory_write"},
                "decision": "allow",
                "risk_score": 35,
                "reason_codes": [],
                "required_controls": ["memory_ttl"],
            },
            {
                "rule_id": "RS-MEM-004",
                "name": "memory_read_is_sandbox_context",
                "category": "memory",
                "match": {"action.semantic_action": "memory_read"},
                "decision": "allow_in_sandbox",
                "risk_score": 45,
                "reason_codes": ["memory_read_as_context"],
                "required_controls": ["memory_taint_check"],
            },
            {
                "rule_id": "DSL-SANDBOX-UNKNOWN-001",
                "name": "unknown_side_effect_requires_preflight",
                "category": "parser",
                "match": {"action.semantic_action": "unknown_side_effect"},
                "decision": "sandbox_then_approval",
                "risk_score": 82,
                "reason_codes": ["default_fail_closed"],
                "required_controls": ["sandbox_preflight", "human_approval"],
            },
            {
                "rule_id": "RS-EDIT-001",
                "name": "contract_matched_source_edit_allowed",
                "category": "edit",
                "match": {"action.semantic_action": "edit_source_file", "contract.match_any": ["match", "partial_match"]},
                "decision": "allow",
                "risk_score": 35,
                "reason_codes": [],
                "required_controls": ["record_diff"],
            },
            {
                "rule_id": "RS-EDIT-002",
                "name": "out_of_contract_source_edit_requires_approval",
                "category": "edit",
                "match": {"action.semantic_action": "edit_source_file", "contract.match_any": ["violation", "unknown"]},
                "decision": "sandbox_then_approval",
                "risk_score": 70,
                "reason_codes": [],
                "required_controls": ["record_diff", "human_approval"],
            },
            {
                "rule_id": "RS-SANDBOX-001",
                "name": "contract_matched_tests_run_in_sandbox",
                "category": "sandbox",
                "match": {"action.semantic_action": "run_tests", "contract.match_any": ["match", "partial_match"]},
                "decision": "allow_in_sandbox",
                "risk_score": 40,
                "reason_codes": [],
                "required_controls": ["sandbox_preflight"],
            },
            {
                "rule_id": "RS-SANDBOX-002",
                "name": "out_of_contract_tests_require_approval",
                "category": "sandbox",
                "match": {"action.semantic_action": "run_tests", "contract.match_any": ["violation", "unknown"]},
                "decision": "sandbox_then_approval",
                "risk_score": 70,
                "reason_codes": [],
                "required_controls": ["sandbox_preflight", "human_approval"],
            },
            {
                "rule_id": "RS-READ-001",
                "name": "project_file_read_allowed",
                "category": "read",
                "match": {"action.semantic_action": "read_project_file"},
                "decision": "allow",
                "risk_score": 30,
                "reason_codes": [],
                "required_controls": [],
            },
        ]


class PolicyEngine:
    """Backward-compatible PolicyEngine entrypoint backed only by PolicyGraph."""

    def __init__(self, mode: str | None = None) -> None:
        self.mode = mode or os.environ.get("REPOSHIELD_POLICY_ENGINE", "policygraph-enforce")
        if self.mode not in VALID_MODES:
            self.mode = "policygraph-enforce"
        self.policygraph = PolicyGraphEngine()
        self._eval_events: list[dict[str, Any]] = []

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
        return graph_decision

    def consume_eval_events(self) -> list[dict[str, Any]]:
        events = self._eval_events
        self._eval_events = []
        return events
