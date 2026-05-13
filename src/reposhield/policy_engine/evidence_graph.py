"""Causal evidence trace emitted by PolicyGraph decisions."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..models import Decision, new_id, utc_now
from .facts import PolicyFactSet
from .rule_schema import RuleHit


@dataclass(slots=True)
class PolicyEvaluationTrace:
    policy_eval_trace_id: str
    action_id: str
    engine_mode: str
    policy_version: str
    fact_set_id: str
    fact_hash: str
    final_decision: Decision
    invariant_hits: list[str]
    rule_hits: list[dict[str, Any]]
    decision_lattice_path: list[dict[str, Any]]
    skipped_rules_summary: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    @classmethod
    def build(
        cls,
        *,
        action_id: str,
        engine_mode: str,
        policy_version: str,
        fact_set: PolicyFactSet,
        final_decision: Decision,
        hits: list[RuleHit],
        lattice_path: list[dict[str, Any]],
        skipped_rules_summary: dict[str, Any] | None = None,
    ) -> "PolicyEvaluationTrace":
        return cls(
            policy_eval_trace_id=new_id("peval"),
            action_id=action_id,
            engine_mode=engine_mode,
            policy_version=policy_version,
            fact_set_id=fact_set.fact_set_id,
            fact_hash=fact_set.content_hash,
            final_decision=final_decision,
            invariant_hits=[h.rule_id for h in hits if h.invariant],
            rule_hits=[asdict(h) for h in hits],
            decision_lattice_path=lattice_path,
            skipped_rules_summary=skipped_rules_summary or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
