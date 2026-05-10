"""Small configurable policy override layer."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from .models import ActionIR, PolicyDecision


class ConfigurablePolicyOverrides:
    """Apply simple YAML/JSON policy overrides after core PolicyEngine.

    Supported shape:
      rules:
        - name: block_ci
          match: {semantic_action: modify_ci_pipeline}
          decision: block
          reason: configured_block_ci
    """

    def __init__(self, rules: list[dict[str, Any]] | None = None):
        self.rules = rules or []

    @classmethod
    def from_file(cls, path: str | Path | None) -> "ConfigurablePolicyOverrides":
        if not path:
            return cls()
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(p)
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(text) or {}
            except ImportError as exc:
                raise RuntimeError("PyYAML is required for YAML policy config; install reposhield[yaml] or use JSON") from exc
        return cls(list((data or {}).get("rules", [])))

    def apply(self, action: ActionIR, decision: PolicyDecision) -> PolicyDecision:
        for rule in self.rules:
            if not self._matches(rule.get("match", {}), action, decision):
                continue
            new_decision = str(rule.get("decision") or decision.decision)
            reason = str(rule.get("reason") or rule.get("name") or "configured_policy_override")
            risk_score = int(rule.get("risk_score") or decision.risk_score)
            controls = list(rule.get("required_controls") or decision.required_controls)
            return replace(
                decision,
                decision=new_decision,  # type: ignore[arg-type]
                risk_score=max(decision.risk_score, risk_score),
                reason_codes=list(dict.fromkeys([*decision.reason_codes, reason])),
                required_controls=list(dict.fromkeys(controls)),
                explanation=str(rule.get("explanation") or decision.explanation),
            )
        return decision

    @staticmethod
    def _matches(match: dict[str, Any], action: ActionIR, decision: PolicyDecision) -> bool:
        if not match:
            return False
        if match.get("semantic_action") and match["semantic_action"] != action.semantic_action:
            return False
        if match.get("tool") and str(match["tool"]).lower() != action.tool.lower():
            return False
        if match.get("risk") and match["risk"] != action.risk:
            return False
        if match.get("decision") and match["decision"] != decision.decision:
            return False
        tag = match.get("risk_tag")
        if tag and tag not in action.risk_tags:
            return False
        return True

