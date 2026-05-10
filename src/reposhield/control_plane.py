"""RepoShield control plane orchestration."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .action_parser import ActionParser
from .asset import AssetScanner
from .audit import AuditLog
from .context import ContextProvenance
from .contract import TaskContractBuilder
from .mcp_proxy import MCPProxy
from .memory import MemoryStore
from .models import ActionIR, PolicyDecision, RepoAssetGraph, SourceRecord, TaskContract
from .package_guard import PackageGuard
from .policy import PolicyEngine
from .policy_config import ConfigurablePolicyOverrides
from .sandbox import SandboxRunner
from .sentry import SecretSentry


class RepoShieldControlPlane:
    """Single façade used by CLIs, adapters and the reference coding agent."""

    def __init__(
        self,
        repo_root: str | Path,
        audit_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        policy_config: str | Path | None = None,
        audit: AuditLog | None = None,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.audit = audit or AuditLog(audit_path or (self.repo_root / ".reposhield" / "audit.jsonl"))
        self.provenance = ContextProvenance()
        self.parser = ActionParser()
        self.asset_scanner = AssetScanner(self.repo_root, env=env)
        self.asset_graph: RepoAssetGraph = self.asset_scanner.scan()
        self.policy = PolicyEngine()
        self.policy_overrides = ConfigurablePolicyOverrides.from_file(policy_config)
        self.package_guard = PackageGuard(self.repo_root)
        self.sandbox = SandboxRunner(self.repo_root)
        self.sentry = SecretSentry(self.asset_graph)
        self.mcp_proxy = MCPProxy(self.provenance)
        self.memory = MemoryStore(self.repo_root / ".reposhield" / "memory.json")
        self.contract_builder = TaskContractBuilder()
        self.contract: TaskContract | None = None
        self.audit.append("asset_scan", asdict(self.asset_graph), actor="asset_scanner")

    def reset_task_context(self) -> None:
        """Start a fresh per-request task context while keeping shared repo services."""
        self.provenance = ContextProvenance()
        self.sentry = SecretSentry(self.asset_graph)
        self.mcp_proxy = MCPProxy(self.provenance)
        self.contract = None

    def ingest_source(self, source_type: str, content: str, retrieval_path: str = "", source_id: str | None = None) -> SourceRecord:
        src = self.provenance.ingest(source_type, content, retrieval_path, source_id=source_id)
        self.audit.append("source_ingested", asdict(src), actor="context_provenance", source_ids=[src.source_id])
        return src

    def build_contract(self, user_prompt: str) -> TaskContract:
        user_src = self.ingest_source("user_request", user_prompt, retrieval_path="current_user")
        contract = self.contract_builder.build(user_prompt)
        self.contract = contract
        self.audit.append("task_contract", asdict(contract), task_id=contract.task_id, actor="contract_builder", source_ids=[user_src.source_id])
        return contract

    def guard_action(
        self,
        raw_action: str,
        source_ids: list[str] | None = None,
        tool: str = "Bash",
        operation: str | None = None,
        file_path: str | None = None,
        run_preflight: bool = True,
    ) -> tuple[ActionIR, PolicyDecision]:
        if self.contract is None:
            self.build_contract("general code maintenance task")
        action = self.parser.parse(raw_action, tool=tool, cwd=self.repo_root, source_ids=source_ids or [], operation=operation, file_path=file_path)
        return self.guard_action_ir(action, run_preflight=run_preflight)

    def guard_action_ir(
        self,
        action: ActionIR,
        *,
        run_preflight: bool = True,
    ) -> tuple[ActionIR, PolicyDecision]:
        """Govern an already-lowered ActionIR without reparsing raw tool input."""
        if self.contract is None:
            self.build_contract("general code maintenance task")
        assert self.contract is not None
        for sid in action.source_ids:
            self.provenance.influence(sid, action.action_id)
        self.audit.append("action_parsed", asdict(action), task_id=self.contract.task_id, actor="action_parser", source_ids=action.source_ids, action_id=action.action_id)

        secret_event = self.sentry.observe_action(action)
        if secret_event:
            self.audit.append("secret_event", asdict(secret_event), task_id=self.contract.task_id, actor="secret_sentry", action_id=action.action_id)

        package_event = self.package_guard.analyze(action)
        if package_event:
            self.audit.append("package_event", asdict(package_event), task_id=self.contract.task_id, actor="package_guard", action_id=action.action_id)

        mcp_invocation = None
        if action.semantic_action in {"invoke_mcp_tool", "invoke_destructive_mcp_tool"}:
            mcp_args = action.metadata.get("mcp_args") if isinstance(action.metadata.get("mcp_args"), dict) else {"raw_action": action.raw_action}
            server_id = str(action.metadata.get("mcp_server_id") or "mcp_adapter")
            tool_name = str(action.metadata.get("mcp_tool_name") or action.raw_action)
            mcp_invocation = self.mcp_proxy.invoke(server_id, tool_name, mcp_args)
            self.audit.append("mcp_invocation", asdict(mcp_invocation), task_id=self.contract.task_id, actor="mcp_proxy", source_ids=action.source_ids, action_id=action.action_id)
            if mcp_invocation.output_source_id:
                self.audit.append("source_ingested", {"source_id": mcp_invocation.output_source_id, "source_type": "mcp_output"}, task_id=self.contract.task_id, actor="mcp_proxy", source_ids=[mcp_invocation.output_source_id], action_id=action.action_id)

        if action.semantic_action == "memory_write":
            record = self.memory.write(action.raw_action, action.source_ids, self.provenance.graph, created_by="control_plane")
            self.audit.append("memory_event", asdict(record), task_id=self.contract.task_id, actor="memory_store", source_ids=action.source_ids, action_id=action.action_id)
        elif action.semantic_action == "memory_read":
            self.audit.append("memory_event", {"event": "memory_read_requested", "raw_action_hash": action.raw_action}, task_id=self.contract.task_id, actor="memory_store", source_ids=action.source_ids, action_id=action.action_id)

        # First decision: may already hard-block before sandbox. Preflight can enrich evidence for high-risk actions.
        decision = self.policy.decide(self.contract, action, self.asset_graph, self.provenance.graph, package_event=package_event, secret_event=secret_event)
        preflight_actions = {
            "install_git_dependency", "install_tarball_dependency", "install_registry_dependency",
            "send_network_request", "read_secret_file", "publish_artifact", "modify_ci_pipeline",
            "modify_registry_config", "git_push_force", "invoke_destructive_mcp_tool", "unknown_side_effect",
        }
        if run_preflight and decision.decision in {"sandbox_then_approval", "block"} and action.semantic_action in preflight_actions:
            trace = self.sandbox.preflight(action, decision=decision, package_event=package_event)
            self.audit.append("exec_trace", asdict(trace), task_id=self.contract.task_id, actor="sandbox", action_id=action.action_id)
            decision = self.policy.decide(self.contract, action, self.asset_graph, self.provenance.graph, package_event=package_event, secret_event=secret_event, exec_trace=trace)

        decision = self.policy_overrides.apply(action, decision)
        for event in self.policy_overrides.consume_events():
            self.audit.append("policy_override_event", event, task_id=self.contract.task_id, actor="policy_config", action_id=action.action_id, decision_id=decision.decision_id)

        self.audit.append("policy_decision", asdict(decision), task_id=self.contract.task_id, actor="policy_engine", source_ids=action.source_ids, action_id=action.action_id, decision_id=decision.decision_id)
        return action, decision

    def scan_report(self) -> dict[str, Any]:
        report = self.asset_scanner.report(self.asset_graph)
        return {"asset_graph": asdict(self.asset_graph), "risk_surface_report": asdict(report)}

    def incident_graph(self) -> dict[str, Any]:
        return self.audit.incident_graph()
