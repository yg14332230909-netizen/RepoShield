"""Policy pack runtime and mode handling."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from ..models import PolicyDecision

PolicyMode = Literal["enforce", "observe_only", "warn", "disabled"]


@dataclass(slots=True)
class PolicyHit:
    policy_name: str
    mode: PolicyMode
    reason_codes: list[str]
    decision: str
    would_block: bool
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuntimePolicyResult:
    effective_decision: str
    original_decision: str
    mode: PolicyMode
    hits: list[PolicyHit]
    warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PolicyRuntime:
    """Wrap the core PolicyEngine decision with enforce/observe/warn behavior."""

    def __init__(self, mode: PolicyMode = "enforce", role: str = "local_dev_strict", *, unsafe_allow_disabled: bool = False) -> None:
        if mode == "disabled" and not unsafe_allow_disabled:
            raise ValueError("policy disabled mode requires explicit unsafe_allow_disabled=True")
        self.mode = mode
        self.role = role
        self.unsafe_allow_disabled = unsafe_allow_disabled

    def apply(self, decision: PolicyDecision, policy_name: str = "CoreRepoShieldPolicy") -> RuntimePolicyResult:
        would_block = decision.decision in {"block", "quarantine", "sandbox_then_approval"}
        hit = PolicyHit(
            policy_name,
            self.mode,
            decision.reason_codes,
            decision.decision,
            would_block,
            {"risk_score": decision.risk_score, "policy_version": decision.policy_version, "unsafe_allow_disabled": self.unsafe_allow_disabled},
        )
        if self.mode == "disabled":
            return RuntimePolicyResult("allow", decision.decision, self.mode, [hit], warning="policy disabled")
        if self.mode == "observe_only":
            return RuntimePolicyResult("allow", decision.decision, self.mode, [hit], warning="observe_only:would_block" if would_block else None)
        if self.mode == "warn":
            effective = "allow_in_sandbox" if would_block else decision.decision
            return RuntimePolicyResult(effective, decision.decision, self.mode, [hit], warning="warning:policy_triggered" if would_block else None)
        return RuntimePolicyResult(decision.decision, decision.decision, self.mode, [hit])
