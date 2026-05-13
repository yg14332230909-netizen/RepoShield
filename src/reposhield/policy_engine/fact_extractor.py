"""Extract typed policy facts from RepoShield evidence objects."""
from __future__ import annotations

from dataclasses import asdict

from ..contract import IntentMatcher
from .context import PolicyEvalContext
from .facts import PolicyFact, PolicyFactSet
from .indexes import AssetIndex, SourceIndex

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
NETWORK_ACTIONS = {"send_network_request", "install_registry_dependency", "install_git_dependency", "install_tarball_dependency", "publish_artifact"}


class FactExtractor:
    def __init__(self) -> None:
        self.matcher = IntentMatcher()

    def extract(self, ctx: PolicyEvalContext) -> PolicyFactSet:
        facts: list[PolicyFact] = []
        action = ctx.action
        source_index = SourceIndex(ctx.context_graph)
        asset_index = AssetIndex(ctx.asset_graph)
        intent = self.matcher.match(ctx.contract, action)
        source_summary = source_index.facts_for(action.source_ids)

        facts.extend(
            [
                PolicyFact.of("action", "semantic_action", action.semantic_action, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "risk", action.risk, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "tool", action.tool, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "side_effect", action.side_effect, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "parser_confidence", action.parser_confidence, evidence_refs=[action.action_id], confidence=action.parser_confidence),
                PolicyFact.of("action", "high_risk", action.semantic_action in HIGH_RISK_ACTIONS, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "network_capability", action.semantic_action in NETWORK_ACTIONS, evidence_refs=[action.action_id]),
                PolicyFact.of("source", "trust_floor", source_summary["trust_floor"], evidence_refs=action.source_ids),
                PolicyFact.of("source", "has_untrusted", source_summary["has_untrusted"], evidence_refs=action.source_ids),
                PolicyFact.of("contract", "match", intent.contract_match, evidence_refs=[ctx.contract.task_id]),
                PolicyFact.of("contract", "violation_reason", intent.violation_reason, evidence_refs=[ctx.contract.task_id]),
            ]
        )
        for tag in action.risk_tags:
            facts.append(PolicyFact.of("action", "risk_tag", tag, evidence_refs=[action.action_id]))

        touched = self._touched_paths(ctx)
        for path in touched:
            classified = asset_index.classify_path(path)
            asset = classified["asset"]
            refs = [action.action_id]
            if asset:
                refs.append(asset.asset_id)
            forbidden = asset_index.forbidden_match(classified["path"], ctx.contract.forbidden_files)
            asset_type = classified["asset_type"] or ("forbidden_file" if forbidden else "unknown")
            facts.extend(
                [
                    PolicyFact.of("asset", "touched_path", classified["path"], evidence_refs=refs),
                    PolicyFact.of("asset", "touched_type", asset_type, evidence_refs=refs, metadata={"path": classified["path"]}),
                    PolicyFact.of("asset", "touched_risk", classified["asset_risk"], evidence_refs=refs, metadata={"path": classified["path"]}),
                    PolicyFact.of("asset", "repo_escape", classified["repo_escape"] or "path_escape_repo_root" in action.risk_tags, evidence_refs=refs, metadata={"path": classified["path"]}),
                    PolicyFact.of("asset", "symlink_escape", classified["symlink_escape"] or "symlink_escape_repo_root" in action.risk_tags, evidence_refs=refs, metadata={"path": classified["path"]}),
                    PolicyFact.of("contract", "forbidden_file_touch", forbidden, evidence_refs=refs, metadata={"path": classified["path"]}),
                ]
            )

        if ctx.package_event:
            pkg = ctx.package_event
            refs = [pkg.package_event_id, action.action_id]
            facts.extend(
                [
                    PolicyFact.of("package", "source", pkg.source, evidence_refs=refs),
                    PolicyFact.of("package", "registry", pkg.registry, evidence_refs=refs),
                    PolicyFact.of("package", "risk", pkg.risk, evidence_refs=refs),
                    PolicyFact.of("package", "lifecycle_scripts", bool(pkg.lifecycle_scripts), evidence_refs=refs, metadata={"scripts": pkg.lifecycle_scripts}),
                    PolicyFact.of("package", "reason_codes", pkg.reason_codes, evidence_refs=refs),
                ]
            )

        if ctx.secret_event:
            sec = ctx.secret_event
            refs = [sec.secret_event_id, action.action_id]
            facts.extend(
                [
                    PolicyFact.of("secret", "event", sec.event, evidence_refs=refs),
                    PolicyFact.of("secret", "asset", sec.asset, evidence_refs=refs),
                    PolicyFact.of("secret", "egress_target", sec.egress_target, evidence_refs=refs),
                ]
            )

        if ctx.exec_trace:
            trace = ctx.exec_trace
            refs = [trace.exec_trace_id, action.action_id]
            facts.extend(
                [
                    PolicyFact.of("sandbox", "network_attempts", bool(trace.network_attempts), evidence_refs=refs, metadata={"network_attempts": trace.network_attempts}),
                    PolicyFact.of("sandbox", "package_scripts", bool(trace.package_scripts), evidence_refs=refs, metadata={"package_scripts": trace.package_scripts}),
                    PolicyFact.of("sandbox", "risk_observed", trace.risk_observed, evidence_refs=refs),
                ]
            )
            for item in trace.files_read:
                facts.append(PolicyFact.of("sandbox", "file_read", item, evidence_refs=refs))
            for item in trace.files_written:
                facts.append(PolicyFact.of("sandbox", "file_written", item, evidence_refs=refs))
            for item in trace.env_access:
                facts.append(PolicyFact.of("sandbox", "env_access", item, evidence_refs=refs))

        mcp_decision = action.metadata.get("mcp_decision")
        if action.semantic_action in {"invoke_mcp_tool", "invoke_destructive_mcp_tool"} or mcp_decision:
            facts.extend(
                [
                    PolicyFact.of("mcp", "decision", mcp_decision, evidence_refs=[action.action_id]),
                    PolicyFact.of("mcp", "capability", action.metadata.get("mcp_capability") or action.semantic_action, evidence_refs=[action.action_id]),
                    PolicyFact.of("mcp", "reason_codes", action.metadata.get("mcp_reason_codes", []), evidence_refs=[action.action_id]),
                ]
            )

        if action.metadata.get("memory_authorization_denied"):
            facts.append(PolicyFact.of("memory", "authorization_denied", True, evidence_refs=[action.action_id], metadata={"denials": action.metadata["memory_authorization_denied"]}))

        facts.append(PolicyFact.of("policy", "eval_context", asdict(ctx), evidence_refs=[action.action_id], metadata={"phase": ctx.phase}))
        return PolicyFactSet(facts)

    @staticmethod
    def _touched_paths(ctx: PolicyEvalContext) -> list[str]:
        paths: list[str] = list(ctx.action.affected_assets)
        if ctx.secret_event and ctx.secret_event.asset:
            paths.append(ctx.secret_event.asset)
        if ctx.exec_trace:
            paths.extend(ctx.exec_trace.files_read)
            paths.extend(ctx.exec_trace.files_written)
            paths.extend([f"env:{name}" if not str(name).startswith("env:") else str(name) for name in ctx.exec_trace.env_access])
        return list(dict.fromkeys([p for p in paths if p]))
