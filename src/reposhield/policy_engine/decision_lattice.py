"""Monotonic decision lattice for merging rule hits."""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..models import Decision, PolicyDecision
from .rule_schema import RuleHit

DECISION_RANK: dict[Decision, int] = {
    "allow": 0,
    "allow_in_sandbox": 1,
    "sandbox_then_approval": 2,
    "quarantine": 3,
    "block": 4,
}


class DecisionLattice:
    def merge(self, baseline: PolicyDecision, hits: list[RuleHit]) -> tuple[PolicyDecision, list[dict[str, Any]]]:
        decision: Decision = baseline.decision
        path: list[dict[str, Any]] = [
            {"from": None, "to": baseline.decision, "via": "legacy_baseline", "rank": DECISION_RANK[baseline.decision]}
        ]
        reasons = list(baseline.reason_codes)
        controls = list(baseline.required_controls)
        risk_score = baseline.risk_score

        for hit in hits:
            hit_rank = DECISION_RANK[hit.decision]
            cur_rank = DECISION_RANK[decision]
            accepted = hit_rank >= cur_rank
            if accepted:
                previous = decision
                decision = hit.decision
                path.append({"from": previous, "to": decision, "via": hit.rule_id, "rank": hit_rank})
            else:
                path.append({"from": decision, "to": decision, "via": hit.rule_id, "rank": cur_rank, "skipped_lower_rank": hit.decision})
            reasons.extend(hit.reason_codes)
            controls.extend(hit.required_controls)
            risk_score = max(risk_score, hit.risk_score)

        matched = [*baseline.matched_rules, *[hit.to_matched_rule() for hit in hits]]
        refs = [*baseline.evidence_refs, *[ref for hit in hits for ref in hit.evidence_refs]]
        return replace(
            baseline,
            decision=decision,
            risk_score=min(risk_score, 100),
            reason_codes=list(dict.fromkeys(reasons)),
            required_controls=list(dict.fromkeys(controls)),
            matched_rules=matched,
            evidence_refs=list(dict.fromkeys(refs)),
        ), path
