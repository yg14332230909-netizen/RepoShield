"""Common adapter protocol objects for external coding agents."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..models import PolicyDecision
from .base import AgentToolCall


@dataclass(slots=True)
class AdapterEvent:
    event_type: str
    message: str
    tool_call: AgentToolCall | None = None
    decision: PolicyDecision | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class AdapterRunResult:
    adapter: str
    repo_root: str
    task: str
    executed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    approval_required: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    audit_log: str | None = None

    @property
    def ok(self) -> bool:
        return True


def parse_reposhield_action_lines(text: str, default_tool: str = "Bash") -> list[AgentToolCall]:
    """Parse a simple generic adapter transcript.

    Supported forms:
      RS_ACTION: npm test
      RUN: npm test
      EDIT: src/login.js
      READ: README.md
    """
    calls: list[AgentToolCall] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("RS_ACTION:") or upper.startswith("RUN:"):
            action = line.split(":", 1)[1].strip()
            if action:
                calls.append(AgentToolCall(action, default_tool, []))
        elif upper.startswith("EDIT:"):
            path = line.split(":", 1)[1].strip()
            calls.append(AgentToolCall(path, "Edit", [], operation="edit", file_path=path))
        elif upper.startswith("READ:"):
            path = line.split(":", 1)[1].strip()
            calls.append(AgentToolCall(path, "Read", [], operation="read", file_path=path))
    return calls


def ensure_repo(path: str | Path) -> Path:
    repo = Path(path).resolve()
    if not repo.exists():
        raise FileNotFoundError(f"repo not found: {repo}")
    return repo
