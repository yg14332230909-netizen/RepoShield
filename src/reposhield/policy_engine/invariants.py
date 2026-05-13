"""Non-downgradable safety invariants for PolicyGraph."""
from __future__ import annotations

from typing import Any

from .facts import PolicyFact, PolicyFactSet
from .rule_schema import RuleHit

SECRET_ASSET_TYPES = {"secret_file", "secret_env", "publish_config", "forbidden_file"}
HIGH_RISK_ACTIONS = {
    "install_registry_dependency",
    "install_git_dependency",
    "install_tarball_dependency",
    "send_network_request",
    "publish_artifact",
    "modify_ci_pipeline",
    "modify_registry_config",
    "git_push_force",
    "invoke_destructive_mcp_tool",
}


class InvariantEngine:
    def evaluate(self, facts: PolicyFactSet) -> list[RuleHit]:
        hits: list[RuleHit] = []
        if self._secret_asset_touched(facts):
            hits.append(self._hit("INV-SECRET-001", "secret_asset_touch", "secret", "block", 100, ["secret_asset_touched"], ["block", "redact", "no_egress"], facts.find("asset", "touched_type") + facts.find("contract", "forbidden_file_touch")))
        if self._secret_egress(facts):
            hits.append(self._hit("INV-EGRESS-001", "secret_egress", "egress", "block", 100, ["secret_egress_attempt"], ["block", "no_egress"], facts.find("secret") + facts.find("action", "network_capability")))
        if self._untrusted_authority(facts):
            hits.append(self._hit("INV-SOURCE-001", "untrusted_authority", "source_authority", "block", 95, ["untrusted_source_cannot_authorize_high_risk_action"], ["block"], facts.find("source") + facts.find("action", "high_risk") + facts.find("contract", "match")))
        if self._repo_escape(facts):
            hits.append(self._hit("INV-REPO-001", "repo_escape", "repo_boundary", "block", 100, ["repo_escape_or_symlink_escape"], ["block"], facts.find("asset", "repo_escape") + facts.find("asset", "symlink_escape")))
        if self._ci_poisoning(facts):
            hits.append(self._hit("INV-CI-001", "ci_cd_touched_by_untrusted_source", "ci", "block", 95, ["untrusted_source_cannot_modify_ci_asset"], ["block", "human_approval"], facts.find("asset", "touched_type") + facts.find("source", "has_untrusted")))
        if self._supply_chain(facts):
            hits.append(self._hit("INV-SC-001", "remote_package_from_untrusted_source", "supply_chain", "block", 95, ["untrusted_source_cannot_authorize_remote_package"], ["block", "package_preflight"], facts.find("package", "source") + facts.find("source", "has_untrusted")))
        if self._mcp_destructive(facts):
            hits.append(self._hit("INV-MCP-001", "destructive_or_blocked_mcp", "mcp", "block", 92, ["destructive_or_blocked_mcp_tool"], ["mcp_proxy", "block"], facts.find("mcp")))
        if self._memory_authorization(facts):
            hits.append(self._hit("INV-MEM-001", "tainted_memory_authorization", "memory", "block", 92, ["memory_authorization_denied_high_risk"], ["memory_taint_gate", "block"], facts.find("memory") + facts.find("action", "high_risk")))
        if self._parser_low_confidence_side_effect(facts):
            hits.append(self._hit("INV-PARSER-001", "low_confidence_side_effect", "parser", "sandbox_then_approval", 82, ["parser_confidence_below_threshold"], ["sandbox_preflight", "human_approval"], facts.find("action", "parser_confidence") + facts.find("action", "side_effect")))
        return hits

    @staticmethod
    def _secret_asset_touched(facts: PolicyFactSet) -> bool:
        return facts.any_value("asset", "touched_type", SECRET_ASSET_TYPES) or any(f.value is True for f in facts.find("contract", "forbidden_file_touch"))

    @staticmethod
    def _secret_egress(facts: PolicyFactSet) -> bool:
        secret_event = facts.any_value("secret", "event", {"egress_after_secret", "token_like_value_in_tool_args"})
        network = any(f.value is True for f in facts.find("action", "network_capability")) or any(f.value is True for f in facts.find("sandbox", "network_attempts"))
        return secret_event and network

    @staticmethod
    def _untrusted_authority(facts: PolicyFactSet) -> bool:
        untrusted = any(f.value is True for f in facts.find("source", "has_untrusted"))
        high_risk = any(f.value is True for f in facts.find("action", "high_risk"))
        contract_mismatch = any(f.value in {"violation", "unknown"} for f in facts.find("contract", "match"))
        return untrusted and high_risk and contract_mismatch

    @staticmethod
    def _repo_escape(facts: PolicyFactSet) -> bool:
        return any(f.value is True for f in facts.find("asset", "repo_escape")) or any(f.value is True for f in facts.find("asset", "symlink_escape"))

    @staticmethod
    def _ci_poisoning(facts: PolicyFactSet) -> bool:
        return facts.any_value("asset", "touched_type", {"ci_workflow"}) and any(f.value is True for f in facts.find("source", "has_untrusted"))

    @staticmethod
    def _supply_chain(facts: PolicyFactSet) -> bool:
        return facts.any_value("package", "source", {"git_url", "tarball_url"}) and any(f.value is True for f in facts.find("source", "has_untrusted"))

    @staticmethod
    def _mcp_destructive(facts: PolicyFactSet) -> bool:
        destructive_caps = {"invoke_destructive_mcp_tool", "deploy", "publish", "delete", "auth", "credential"}
        return facts.any_value("mcp", "decision", {"blocked"}) or any(str(f.value).lower() in destructive_caps for f in facts.find("mcp", "capability"))

    @staticmethod
    def _memory_authorization(facts: PolicyFactSet) -> bool:
        denied = any(f.value is True for f in facts.find("memory", "authorization_denied"))
        high_risk = any(f.value is True for f in facts.find("action", "high_risk"))
        return denied and high_risk

    @staticmethod
    def _parser_low_confidence_side_effect(facts: PolicyFactSet) -> bool:
        low_conf = any(isinstance(f.value, (int, float)) and f.value < 0.6 for f in facts.find("action", "parser_confidence"))
        side_effect = any(f.value is True for f in facts.find("action", "side_effect"))
        return low_conf and side_effect

    @staticmethod
    def _hit(rule_id: str, name: str, category: str, decision: str, risk_score: int, reasons: list[str], controls: list[str], evidence_facts: list[PolicyFact]) -> RuleHit:
        refs = [ref for fact in evidence_facts for ref in fact.evidence_refs]
        predicates: list[dict[str, Any]] = [
            {"fact_id": fact.fact_id, "namespace": fact.namespace, "key": fact.key, "value": fact.value, "matched": True}
            for fact in evidence_facts[:20]
        ]
        return RuleHit(
            rule_id=rule_id,
            name=name,
            category=category,
            decision=decision,  # type: ignore[arg-type]
            risk_score=risk_score,
            reason_codes=reasons,
            required_controls=controls,
            evidence_refs=list(dict.fromkeys(refs)),
            invariant=True,
            predicates=predicates,
        )
