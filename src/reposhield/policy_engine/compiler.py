"""Tiny PolicyGraph DSL compiler."""
from __future__ import annotations

from typing import Any

from .rule_schema import CompiledPolicyRule


class PolicyRuleCompiler:
    def compile(self, raw_rules: list[dict[str, Any]]) -> list[CompiledPolicyRule]:
        rules: list[CompiledPolicyRule] = []
        for item in raw_rules:
            rule_id = str(item.get("rule_id") or item.get("id") or "")
            if not rule_id:
                raise ValueError("policy rule missing rule_id")
            decision = str(item.get("decision") or "sandbox_then_approval")
            if decision not in {"allow", "allow_in_sandbox", "sandbox_then_approval", "quarantine", "block"}:
                raise ValueError(f"invalid decision for {rule_id}: {decision}")
            rules.append(
                CompiledPolicyRule(
                    rule_id=rule_id,
                    name=str(item.get("name") or rule_id),
                    category=str(item.get("category") or "domain"),
                    match=dict(item.get("match") or {}),
                    decision=decision,  # type: ignore[arg-type]
                    risk_score=int(item.get("risk_score") or 70),
                    reason_codes=[str(r) for r in item.get("reason_codes", [])] or [rule_id.lower()],
                    required_controls=[str(c) for c in item.get("required_controls", [])],
                )
            )
        return rules
