"""Predicate evaluator for compiled PolicyGraph rules."""
from __future__ import annotations

from .facts import PolicyFactSet
from .rule_schema import CompiledPolicyRule, RuleHit


class RuleEvaluator:
    def evaluate(self, rules: list[CompiledPolicyRule], facts: PolicyFactSet) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for rule in rules:
            if self._matches(rule, facts):
                hits.append(
                    RuleHit(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        category=rule.category,
                        decision=rule.decision,
                        risk_score=rule.risk_score,
                        reason_codes=rule.reason_codes,
                        required_controls=rule.required_controls,
                        evidence_refs=[],
                        invariant=False,
                        predicates=[{"match": rule.match, "matched": True}],
                    )
                )
        return hits

    @staticmethod
    def _matches(rule: CompiledPolicyRule, facts: PolicyFactSet) -> bool:
        match = rule.match
        for key, expected in match.items():
            namespace, _, fact_key = key.partition(".")
            values = facts.values(namespace, fact_key.removesuffix("_any"))
            if key.endswith("_any"):
                expected_values = set(expected if isinstance(expected, list) else [expected])
                if not any(value in expected_values for value in values):
                    return False
            else:
                if expected not in values:
                    return False
        return True
