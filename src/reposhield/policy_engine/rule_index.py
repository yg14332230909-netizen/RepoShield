"""Candidate rule index for PolicyGraph DSL rules."""
from __future__ import annotations

from .facts import PolicyFactSet
from .rule_schema import CompiledPolicyRule


class RuleIndex:
    def __init__(self, rules: list[CompiledPolicyRule]):
        self.rules = rules
        self.by_semantic: dict[str, list[CompiledPolicyRule]] = {}
        for rule in rules:
            values = rule.match.get("action.semantic_any") or rule.match.get("action.semantic_action")
            candidates = values if isinstance(values, list) else [values] if values else []
            for value in candidates:
                self.by_semantic.setdefault(str(value), []).append(rule)

    def candidates(self, facts: PolicyFactSet) -> tuple[list[CompiledPolicyRule], dict[str, int]]:
        semantics = [str(v) for v in facts.values("action", "semantic_action")]
        selected: list[CompiledPolicyRule] = []
        for semantic in semantics:
            selected.extend(self.by_semantic.get(semantic, []))
        selected.extend([r for r in self.rules if not (r.match.get("action.semantic_any") or r.match.get("action.semantic_action"))])
        dedup = list({rule.rule_id: rule for rule in selected}.values())
        return dedup, {"total_rules": len(self.rules), "candidate_rules": len(dedup)}
