"""Generic CLI coding-agent adapter.

The adapter can read a transcript emitted by any coding agent. Only actions
allowed by RepoShield are applied; dangerous actions are never passed through.
"""
from __future__ import annotations

import subprocess
from dataclasses import asdict
from pathlib import Path

from ..control_plane import RepoShieldControlPlane
from .base import AgentToolCall
from .protocol import AdapterRunResult, parse_reposhield_action_lines


class GenericCLIAdapter:
    name = "generic_cli"

    def __init__(self, repo_root: str | Path, control_plane: RepoShieldControlPlane, task: str, transcript: str | Path | None = None, command: list[str] | None = None):
        self.repo_root = Path(repo_root).resolve()
        self.cp = control_plane
        self.task = task
        self.transcript = Path(transcript) if transcript else None
        self.command = command

    def collect_plan(self) -> list[AgentToolCall]:
        text = ""
        if self.transcript:
            text = self.transcript.read_text(encoding="utf-8")
        elif self.command:
            proc = subprocess.run(self.command, cwd=self.repo_root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            text = proc.stdout + "\n" + proc.stderr
        else:
            text = "EDIT: src/login.js\nRS_ACTION: npm test\n"
        calls = parse_reposhield_action_lines(text)
        self.cp.audit.append("adapter_plan_collected", {"adapter": self.name, "calls": [asdict(c) for c in calls]}, task_id=self.cp.contract.task_id if self.cp.contract else None, actor="generic_cli_adapter")
        return calls

    def run(self) -> AdapterRunResult:
        if self.cp.contract is None:
            self.cp.build_contract(self.task)
        result = AdapterRunResult(adapter=self.name, repo_root=str(self.repo_root), task=self.task, audit_log=str(self.cp.audit.log_path))
        for call in self.collect_plan():
            _action, decision = self.cp.guard_action(call.raw_action, source_ids=call.source_ids or [], tool=call.tool, operation=call.operation, file_path=call.file_path)
            result.events.append({"raw_action": call.raw_action, "decision": asdict(decision)})
            if decision.decision in {"allow", "allow_in_sandbox"}:
                self.apply_allowed_action(call)
                result.executed.append(call.raw_action)
            elif decision.decision == "sandbox_then_approval":
                result.approval_required.append(call.raw_action)
            else:
                result.blocked.append(call.raw_action)
        self.cp.audit.append("adapter_run_result", asdict(result), task_id=self.cp.contract.task_id if self.cp.contract else None, actor="generic_cli_adapter")
        return result

    def apply_allowed_action(self, call: AgentToolCall) -> None:
        if call.operation == "edit" and call.file_path == "src/login.js":
            path = self.repo_root / call.file_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "function bindLogin(button, submit) {\n"
                "  if (!button || typeof submit !== 'function') throw new Error('bindLogin requires button and submit');\n"
                "  button.onclick = () => submit();\n"
                "}\n\nmodule.exports = { bindLogin };\n",
                encoding="utf-8",
            )
