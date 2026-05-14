"""Tiny PolicyGraph DSL compiler."""
from __future__ import annotations

from typing import Any

from .rule_schema import CompiledPolicyRule

VALID_DECISIONS = {"allow", "allow_in_sandbox", "sandbox_then_approval", "quarantine", "block"}
VALID_OPERATORS = {"eq", "in", "exists", "not_exists", "contains", "regex", "gte", "lte"}


class PolicyRuleCompiler:
    def compile(self, raw_rules: list[dict[str, Any]]) -> list[CompiledPolicyRule]:
        rules: list[CompiledPolicyRule] = []
        for item in raw_rules:
            rule_id = str(item.get("rule_id") or item.get("id") or "")
            if not rule_id:
                raise ValueError("policy rule missing rule_id")
            decision = str(item.get("decision") or "sandbox_then_approval")
            if decision not in VALID_DECISIONS:
                raise ValueError(f"invalid decision for {rule_id}: {decision}")
            predicates = self._normalise_predicates(dict(item.get("match") or {}), list(item.get("predicates") or []), rule_id)
            unless = self._normalise_unless(item.get("unless"), rule_id)
            rules.append(
                CompiledPolicyRule(
                    rule_id=rule_id,
                    name=str(item.get("name") or rule_id),
                    category=str(item.get("category") or "domain"),
                    match=dict(item.get("match") or {}),
                    decision=decision,  # type: ignore[arg-type]
                    risk_score=int(item.get("risk_score") or 70),
                    reason_codes=[str(r) for r in item.get("reason_codes", [])] or [rule_id.lower()],
                    predicates=predicates,
                    unless=unless,
                    required_controls=[str(c) for c in item.get("required_controls", [])],
                )
            )
        return rules

    def validate(self, raw_rules: list[dict[str, Any]]) -> list[str]:
        errors: list[str] = []
        try:
            self.compile(raw_rules)
        except ValueError as exc:
            errors.append(str(exc))
        return errors

    def _normalise_predicates(self, match: dict[str, Any], predicates: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
        normalised: list[dict[str, Any]] = []
        for path, expected in match.items():
            if path in {"any", "all", "unless"}:
                continue
            op = "in" if path.endswith("_any") or isinstance(expected, list) else "eq"
            normalised.append({"path": self._path(path), "operator": op, "expected": expected})
        for pred in predicates:
            if not isinstance(pred, dict):
                raise ValueError(f"{rule_id}: predicate must be an object")
            op = str(pred.get("operator") or "eq")
            if op not in VALID_OPERATORS:
                raise ValueError(f"{rule_id}: unsupported operator {op}")
            path = str(pred.get("path") or "")
            if not path:
                raise ValueError(f"{rule_id}: predicate.path is required")
            normalised.append({"path": self._path(path), "operator": op, "expected": pred.get("expected")})
        for group in ("any", "all"):
            if group in match:
                items = match[group] if isinstance(match[group], list) else [match[group]]
                children = []
                for item in items:
                    if not isinstance(item, dict):
                        raise ValueError(f"{rule_id}: {group} predicate entries must be objects")
                    children.extend(self._normalise_predicates(item, [], rule_id))
                normalised.append({"operator": group, "predicates": children, "path": group, "expected": None})
        return normalised

    def _normalise_unless(self, unless: Any, rule_id: str) -> list[dict[str, Any]]:
        if not unless:
            return []
        items = unless if isinstance(unless, list) else [unless]
        normalised: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{rule_id}: unless entries must be objects")
            normalised.extend(self._normalise_predicates(item, [], rule_id))
        return normalised

    @staticmethod
    def _path(path: str) -> str:
        namespace, _, key = path.partition(".")
        key = key.removesuffix("_any")
        if namespace == "action" and key == "semantic":
            key = "semantic_action"
        return f"{namespace}.{key}"
