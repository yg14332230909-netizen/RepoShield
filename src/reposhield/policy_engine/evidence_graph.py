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
    fact_nodes: list[dict[str, Any]] = field(default_factory=list)
    predicate_nodes: list[dict[str, Any]] = field(default_factory=list)
    rule_nodes: list[dict[str, Any]] = field(default_factory=list)
    lattice_nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, str]] = field(default_factory=list)
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
        graph = _causal_graph(fact_set, hits, lattice_path)
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
            fact_nodes=graph["fact_nodes"],
            predicate_nodes=graph["predicate_nodes"],
            rule_nodes=graph["rule_nodes"],
            lattice_nodes=graph["lattice_nodes"],
            edges=graph["edges"],
            decision_lattice_path=lattice_path,
            skipped_rules_summary=skipped_rules_summary or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _causal_graph(fact_set: PolicyFactSet, hits: list[RuleHit], lattice_path: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    fact_nodes = [
        {
            "id": fact.fact_id,
            "fact_id": fact.fact_id,
            "namespace": fact.namespace,
            "key": fact.key,
            "value": fact.value,
            "evidence_refs": fact.evidence_refs,
        }
        for fact in fact_set.facts
    ]
    predicate_nodes: list[dict[str, Any]] = []
    rule_nodes: list[dict[str, Any]] = []
    lattice_nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    for hit in hits:
        predicate_ids: list[str] = []
        for pred in hit.predicates:
            p = asdict(pred) if hasattr(pred, "__dataclass_fields__") else dict(pred)
            pred_id = str(p.get("predicate_id") or p.get("fact_id") or new_id("pred"))
            p["id"] = pred_id
            p["rule_id"] = hit.rule_id
            predicate_nodes.append(p)
            predicate_ids.append(pred_id)
            for fact_id in p.get("matched_fact_ids", []) or ([p.get("fact_id")] if p.get("fact_id") else []):
                edges.append({"from": str(fact_id), "to": pred_id, "relation": "matched"})
            edges.append({"from": pred_id, "to": hit.rule_id, "relation": "predicate_of"})
        rule_nodes.append({"id": hit.rule_id, "rule_id": hit.rule_id, "decision": hit.decision, "invariant": hit.invariant, "predicate_ids": predicate_ids})
    previous = ""
    for idx, step in enumerate(lattice_path):
        node_id = f"lattice_{idx}"
        lattice_nodes.append({"id": node_id, **step})
        via = str(step.get("via") or "")
        if via and via != "policygraph_baseline":
            edges.append({"from": via, "to": node_id, "relation": "merged_into"})
        if previous:
            edges.append({"from": previous, "to": node_id, "relation": "next"})
        previous = node_id
    if previous:
        edges.append({"from": previous, "to": "final_decision", "relation": "final"})
    return {
        "fact_nodes": fact_nodes,
        "predicate_nodes": predicate_nodes,
        "rule_nodes": rule_nodes,
        "lattice_nodes": lattice_nodes,
        "edges": edges,
    }
