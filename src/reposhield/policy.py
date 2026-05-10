"""Risk scoring and policy decisions."""
from __future__ import annotations

from .contract import IntentMatcher
from .models import (
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

RISK_SCORE = {"low": 15, "medium": 40, "high": 70, "critical": 95}


class PolicyEngine:
    policy_version = "reposhield-policy-v0.2"

    def __init__(self) -> None:
        self.matcher = IntentMatcher()

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
        intent = self.matcher.match(contract, action)
        reason_codes: list[str] = []
        controls: list[str] = []
        score = RISK_SCORE[action.risk]

        if context_graph.has_untrusted(action.source_ids):
            reason_codes.append("influenced_by_untrusted_source")
            score += 12
        if intent.contract_match in {"violation", "unknown"}:
            reason_codes.extend(intent.violation_reason or ["contract_violation"])
            score += 15
        elif intent.contract_match == "partial_match":
            reason_codes.extend(intent.violation_reason)
            score += 8

        if package_event:
            reason_codes.extend(package_event.reason_codes)
            if package_event.lifecycle_scripts:
                reason_codes.append("package_lifecycle_script_possible")
                controls.extend(["no_lifecycle_script", "secret_mount_masked"])
            if package_event.source in {"git_url", "tarball_url"}:
                controls.append("package_preflight")
                score += 15
            if package_event.risk == "critical":
                score += 10

        if secret_event:
            reason_codes.append(secret_event.event)
            controls.append("no_egress")
            score += 20

        if exec_trace:
            if exec_trace.network_attempts:
                reason_codes.append("sandbox_network_egress_attempt")
                score += 15
            if exec_trace.package_scripts:
                reason_codes.append("sandbox_lifecycle_observed")
            if "secret_access" in exec_trace.risk_observed:
                reason_codes.append("sandbox_secret_access_observed")
                score += 20

        score = min(score, 100)

        # Hard deny wins over everything.
        if action.semantic_action == "read_secret_file":
            return self._decision(action, "block", 100, [*reason_codes, "hard_deny_read_secret"], ["block"], "Secret reads are hard-denied.", intent, package_event, exec_trace)
        if secret_event and secret_event.event in {"egress_after_secret", "token_like_value_in_tool_args"} and action.semantic_action == "send_network_request":
            return self._decision(action, "block", 100, [*reason_codes, "hard_deny_secret_egress"], ["block", "no_egress"], "Secret-tainted egress is hard-denied.", intent, package_event, exec_trace)
        if action.semantic_action in {"publish_artifact", "git_push_force"}:
            return self._decision(action, "block", max(score, 95), [*reason_codes, "requires_double_approval"], ["block", "double_approval", "dry_run_only"], "Release or force-push actions require stronger approval and are blocked here.", intent, package_event, exec_trace)
        if action.semantic_action == "modify_registry_config":
            return self._decision(action, "block", max(score, 92), [*reason_codes, "registry_config_change"], ["block_or_admin_approval"], "Registry configuration changes are blocked.", intent, package_event, exec_trace)
        if action.semantic_action == "modify_ci_pipeline" and context_graph.has_untrusted(action.source_ids):
            return self._decision(action, "block", max(score, 92), [*reason_codes, "untrusted_source_cannot_modify_ci"], ["block_or_human_approval"], "Untrusted sources cannot authorize CI/CD edits.", intent, package_event, exec_trace)

        # Package supply-chain rules.
        if action.semantic_action in {"install_git_dependency", "install_tarball_dependency"}:
            if context_graph.has_untrusted(action.source_ids) or intent.contract_match in {"violation", "unknown"}:
                return self._decision(action, "block", max(score, 95), [*reason_codes, "untrusted_source_cannot_authorize_dependency_install"], ["block", "package_preflight"], "Untrusted or out-of-contract dependency installs are blocked.", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 87), reason_codes, ["package_preflight", "network_off", "human_approval"], "Remote dependency installs require sandbox preflight and approval.", intent, package_event, exec_trace)

        if action.semantic_action == "install_registry_dependency":
            if intent.contract_match == "violation" and context_graph.has_untrusted(action.source_ids):
                return self._decision(action, "block", max(score, 88), [*reason_codes, "contract_violation"], ["block"], "Untrusted registry install violates the task contract.", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 78), reason_codes, ["package_preflight", "network_allowlist", "secret_mount_masked", "human_approval"], "Registry installs require sandbox preflight and approval.", intent, package_event, exec_trace)

        if action.semantic_action == "send_network_request":
            if context_graph.has_untrusted(action.source_ids):
                return self._decision(action, "block", max(score, 90), [*reason_codes, "untrusted_source_cannot_authorize_network"], ["block", "no_egress"], "Untrusted sources cannot authorize network egress.", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 78), reason_codes, ["network_allowlist", "human_approval"], "Network egress requires approval.", intent, package_event, exec_trace)

        if action.semantic_action == "invoke_destructive_mcp_tool":
            return self._decision(action, "block", max(score, 90), [*reason_codes, "destructive_mcp_tool"], ["mcp_proxy", "human_approval"], "Destructive MCP tools are blocked.", intent, package_event, exec_trace)

        if action.semantic_action == "memory_write":
            if context_graph.has_untrusted(action.source_ids):
                return self._decision(action, "allow_in_sandbox", max(score, 60), [*reason_codes, "tainted_memory_write"], ["memory_taint", "ttl"], "Memory writes influenced by untrusted context are tainted and cannot authorize high-risk actions.", intent, package_event, exec_trace)
            return self._decision(action, "allow", max(score, 35), reason_codes, ["memory_ttl"], "Trusted memory write is allowed with TTL.", intent, package_event, exec_trace)

        if action.semantic_action == "memory_read":
            return self._decision(action, "allow_in_sandbox", max(score, 45), [*reason_codes, "memory_read_as_context"], ["memory_taint_check"], "Memory reads are treated as context and rechecked for taint.", intent, package_event, exec_trace)

        if action.semantic_action == "unknown_side_effect":
            return self._decision(action, "sandbox_then_approval", max(score, 82), [*reason_codes, "parser_confidence_below_threshold"], ["sandbox_preflight", "human_approval"], "Unknown side effects fail closed.", intent, package_event, exec_trace)

        if action.semantic_action == "edit_source_file":
            if intent.contract_match in {"match", "partial_match"}:
                return self._decision(action, "allow", max(score, 35), reason_codes, ["record_diff"], "Contract-matched source edit is allowed on the host with diff recording.", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 70), reason_codes, ["record_diff", "human_approval"], "Source edit is outside the task contract.", intent, package_event, exec_trace)

        if action.semantic_action == "run_tests":
            if intent.contract_match in {"match", "partial_match"}:
                return self._decision(action, "allow_in_sandbox", max(score, 40), reason_codes, ["sandbox_preflight"], "Test execution is constrained to sandbox, overlay, or preflight.", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 70), reason_codes, ["sandbox_preflight", "human_approval"], "Test execution is outside the task contract.", intent, package_event, exec_trace)

        if action.semantic_action == "read_project_file":
            return self._decision(action, "allow", min(score, 30), reason_codes, [], "Project file read is allowed.", intent, package_event, exec_trace)

        return self._decision(action, "sandbox_then_approval", score, reason_codes or ["default_fail_closed"], ["sandbox_preflight", "human_approval"], "Default fail-closed decision.", intent, package_event, exec_trace)

    def _decision(self, action: ActionIR, decision: str, score: int, reasons: list[str], controls: list[str], explanation: str, intent: IntentDiff | None, package_event: PackageEvent | None, exec_trace: ExecTrace | None) -> PolicyDecision:
        # Stable unique reason/control lists while preserving order.
        dedup_reasons = list(dict.fromkeys(reasons))
        dedup_controls = list(dict.fromkeys(controls))
        matched_rules = self._matched_rules(action, decision, dedup_reasons)
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
            matched_rules=matched_rules,
            evidence_refs=list(dict.fromkeys(evidence_refs)),
            policy_version=self.policy_version,
            rule_trace=[
                {
                    "semantic_action": action.semantic_action,
                    "risk": action.risk,
                    "source_ids": action.source_ids,
                    "reason_codes": dedup_reasons,
                    "decision": decision,
                }
            ],
        )

    def _matched_rules(self, action: ActionIR, decision: str, reason_codes: list[str]) -> list[dict[str, str]]:
        rule_id = "RS-DEFAULT-001"
        category = "default"
        if action.semantic_action == "read_secret_file":
            rule_id, category = "RS-SECRET-001", "secret"
        elif action.semantic_action in {"install_git_dependency", "install_tarball_dependency", "install_registry_dependency"}:
            rule_id, category = "RS-SC-001", "supply_chain"
        elif action.semantic_action in {"send_network_request"}:
            rule_id, category = "RS-NET-001", "egress"
        elif action.semantic_action in {"modify_ci_pipeline", "publish_artifact", "git_push_force"}:
            rule_id, category = "RS-RELEASE-001", "release"
        elif action.semantic_action in {"invoke_mcp_tool", "invoke_destructive_mcp_tool"}:
            rule_id, category = "RS-MCP-001", "mcp"
        elif action.semantic_action in {"memory_write", "memory_read"}:
            rule_id, category = "RS-MEM-001", "memory"
        elif action.semantic_action in {"run_tests"}:
            rule_id, category = "RS-SANDBOX-001", "sandbox"
        elif action.semantic_action in {"unknown_side_effect"}:
            rule_id, category = "RS-PARSER-001", "parser"
        return [
            {
                "rule_id": rule_id,
                "name": category,
                "category": category,
                "decision": decision,
                "reason_codes": ",".join(reason_codes),
            }
        ]
