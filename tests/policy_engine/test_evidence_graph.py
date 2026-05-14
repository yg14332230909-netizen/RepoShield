from reposhield.policy_engine.evidence_graph import PolicyEvaluationTrace
from reposhield.policy_engine.facts import PolicyFact, PolicyFactSet
from reposhield.policy_engine.rule_schema import RuleHit


def test_policy_eval_trace_contains_causal_graph_edges():
    fact = PolicyFact.of("asset", "touched_type", "secret_file", evidence_refs=["asset_1"])
    hit = RuleHit(
        "INV-SECRET-001",
        "secret",
        "secret",
        "block",
        100,
        ["secret_asset_touched"],
        ["block"],
        ["asset_1"],
        True,
        [{"predicate_id": "pred_1", "path": "asset.touched_type", "operator": "in", "expected": ["secret_file"], "actual": ["secret_file"], "matched": True, "matched_fact_ids": [fact.fact_id], "evidence_refs": ["asset_1"]}],
    )

    trace = PolicyEvaluationTrace.build(
        action_id="act_1",
        engine_mode="policygraph-enforce",
        policy_version="reposhield-policygraph-v0.4",
        fact_set=PolicyFactSet([fact]),
        final_decision="block",
        hits=[hit],
        lattice_path=[{"from": "allow", "to": "block", "via": "INV-SECRET-001"}],
    )

    assert trace.fact_nodes
    assert trace.predicate_nodes
    assert trace.rule_nodes
    assert {"from": fact.fact_id, "to": "pred_1", "relation": "matched"} in trace.edges
