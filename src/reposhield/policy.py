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
            return self._decision(action, "block", 100, [*reason_codes, "hard_deny_read_secret"], ["block"], "读取敏感文件属于硬阻断。", intent, package_event, exec_trace)
        if secret_event and secret_event.event in {"egress_after_secret", "token_like_value_in_tool_args"} and action.semantic_action == "send_network_request":
            return self._decision(action, "block", 100, [*reason_codes, "hard_deny_secret_egress"], ["block", "no_egress"], "secret taint 后的外发被阻断。", intent, package_event, exec_trace)
        if action.semantic_action in {"publish_artifact", "git_push_force"}:
            return self._decision(action, "block", max(score, 95), [*reason_codes, "requires_double_approval"], ["block", "double_approval", "dry_run_only"], "发布/强推不能由 agent 自主执行。", intent, package_event, exec_trace)
        if action.semantic_action == "modify_registry_config":
            return self._decision(action, "block", max(score, 92), [*reason_codes, "registry_config_change"], ["block_or_admin_approval"], "registry 配置变更可能造成供应链污染。", intent, package_event, exec_trace)
        if action.semantic_action == "modify_ci_pipeline" and context_graph.has_untrusted(action.source_ids):
            return self._decision(action, "block", max(score, 92), [*reason_codes, "untrusted_source_cannot_modify_ci"], ["block_or_human_approval"], "不可信上下文不能授权修改 CI/CD。", intent, package_event, exec_trace)

        # Package supply-chain rules.
        if action.semantic_action in {"install_git_dependency", "install_tarball_dependency"}:
            if context_graph.has_untrusted(action.source_ids) or intent.contract_match in {"violation", "unknown"}:
                return self._decision(action, "block", max(score, 95), [*reason_codes, "untrusted_source_cannot_authorize_dependency_install"], ["block", "package_preflight"], "不可信来源影响且合同外的外部依赖安装被阻断。", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 87), reason_codes, ["package_preflight", "network_off", "human_approval"], "外部依赖安装必须先预演再审批。", intent, package_event, exec_trace)

        if action.semantic_action == "install_registry_dependency":
            if intent.contract_match == "violation" and context_graph.has_untrusted(action.source_ids):
                return self._decision(action, "block", max(score, 88), [*reason_codes, "contract_violation"], ["block"], "合同外且受不可信来源影响的依赖安装被阻断。", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 78), reason_codes, ["package_preflight", "network_allowlist", "secret_mount_masked", "human_approval"], "registry 依赖安装需要预演和审批。", intent, package_event, exec_trace)

        if action.semantic_action == "send_network_request":
            if context_graph.has_untrusted(action.source_ids):
                return self._decision(action, "block", max(score, 90), [*reason_codes, "untrusted_source_cannot_authorize_network"], ["block", "no_egress"], "不可信来源不能授权外发网络请求。", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 78), reason_codes, ["network_allowlist", "human_approval"], "网络请求需要策略检查。", intent, package_event, exec_trace)

        if action.semantic_action == "invoke_destructive_mcp_tool":
            return self._decision(action, "block", max(score, 90), [*reason_codes, "destructive_mcp_tool"], ["mcp_proxy", "human_approval"], "高危 MCP 工具调用需要审批，默认阻断。", intent, package_event, exec_trace)

        if action.semantic_action == "unknown_side_effect":
            return self._decision(action, "sandbox_then_approval", max(score, 82), [*reason_codes, "parser_confidence_below_threshold"], ["sandbox_preflight", "human_approval"], "无法解析且有副作用的动作按 fail-closed 处理。", intent, package_event, exec_trace)

        if action.semantic_action in {"run_tests", "edit_source_file"}:
            if intent.contract_match in {"match", "partial_match"}:
                return self._decision(action, "allow_in_sandbox" if action.side_effect else "allow", max(score, 40), reason_codes, ["record_diff"] if action.side_effect else [], "合同内开发动作允许。", intent, package_event, exec_trace)
            return self._decision(action, "sandbox_then_approval", max(score, 70), reason_codes, ["record_diff", "human_approval"], "开发动作超出合同范围。", intent, package_event, exec_trace)

        if action.semantic_action == "read_project_file":
            return self._decision(action, "allow", min(score, 30), reason_codes, [], "普通项目文件读取允许。", intent, package_event, exec_trace)

        return self._decision(action, "sandbox_then_approval", score, reason_codes or ["default_fail_closed"], ["sandbox_preflight", "human_approval"], "默认 fail-closed。", intent, package_event, exec_trace)

    def _decision(self, action: ActionIR, decision: str, score: int, reasons: list[str], controls: list[str], explanation: str, intent: IntentDiff | None, package_event: PackageEvent | None, exec_trace: ExecTrace | None) -> PolicyDecision:
        # stable unique reason/control lists while preserving order
        dedup_reasons = list(dict.fromkeys(reasons))
        dedup_controls = list(dict.fromkeys(controls))
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
        )
