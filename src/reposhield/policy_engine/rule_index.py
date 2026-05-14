"""Candidate rule index for PolicyGraph DSL rules."""
from __future__ import annotations

from collections import defaultdict

from .facts import PolicyFactSet
from .rule_schema import CompiledPolicyRule

INDEXED_PATHS = {
    "action.semantic_action": "by_action_semantic",
    "action.risk": "by_action_risk",
    "source.trust_floor": "by_source_trust",
    "asset.touched_type": "by_asset_type",
    "package.source": "by_package_source",
    "secret.event": "by_secret_event",
    "contract.match": "by_contract_match",
    "mcp.capability": "by_mcp_capability",
    "sandbox.risk_observed": "by_sandbox_observation",
}


class RuleIndex:
    def __init__(self, rules: list[CompiledPolicyRule]):
        self.rules = rules
        self.indexes: dict[str, dict[str, list[CompiledPolicyRule]]] = {name: defaultdict(list) for name in INDEXED_PATHS.values()}
        self.global_rules: list[CompiledPolicyRule] = []
        for rule in rules:
            indexed = False
            for pred in rule.predicates:
                path = str(pred.get("path") or "")
                if path not in INDEXED_PATHS:
                    continue
                values = self._expected_values(pred)
                if not values:
                    continue
                indexed = True
                bucket = self.indexes[INDEXED_PATHS[path]]
                for value in values:
                    bucket[str(value)].append(rule)
            if not indexed:
                self.global_rules.append(rule)

    def candidates(self, facts: PolicyFactSet) -> tuple[list[CompiledPolicyRule], dict[str, int]]:
        selected: dict[str, CompiledPolicyRule] = {rule.rule_id: rule for rule in self.global_rules}
        lookups = {
            "by_action_semantic": facts.values("action", "semantic_action"),
            "by_action_risk": facts.values("action", "risk"),
            "by_source_trust": facts.values("source", "trust_floor"),
            "by_asset_type": facts.values("asset", "touched_type"),
            "by_package_source": facts.values("package", "source"),
            "by_secret_event": facts.values("secret", "event"),
            "by_contract_match": facts.values("contract", "match"),
            "by_mcp_capability": facts.values("mcp", "capability"),
            "by_sandbox_observation": self._flatten(facts.values("sandbox", "risk_observed")),
        }
        candidate_counts: dict[str, int] = {}
        for index_name, values in lookups.items():
            before = len(selected)
            bucket = self.indexes[index_name]
            for value in values:
                for rule in bucket.get(str(value), []):
                    selected[rule.rule_id] = rule
            candidate_counts[index_name] = len(selected) - before
        dedup = list(selected.values())
        stats = {
            "total_rules": len(self.rules),
            "candidate_rules": len(dedup),
            "global_rules": len(self.global_rules),
            **candidate_counts,
        }
        return dedup, stats

    @staticmethod
    def _expected_values(pred: dict) -> list[object]:
        op = pred.get("operator")
        expected = pred.get("expected")
        if op == "exists" or op == "not_exists" or expected is None:
            return []
        return expected if isinstance(expected, list) else [expected]

    @staticmethod
    def _flatten(values: list[object]) -> list[object]:
        out: list[object] = []
        for value in values:
            if isinstance(value, list):
                out.extend(value)
            else:
                out.append(value)
        return out
