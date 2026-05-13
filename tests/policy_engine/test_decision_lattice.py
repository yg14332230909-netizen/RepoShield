from reposhield.models import PolicyDecision
from reposhield.policy_engine.decision_lattice import DECISION_RANK, DecisionLattice
from reposhield.policy_engine.rule_schema import RuleHit


def test_decision_lattice_order_matches_policygraph_doc():
    assert DECISION_RANK["allow"] < DECISION_RANK["allow_in_sandbox"]
    assert DECISION_RANK["allow_in_sandbox"] < DECISION_RANK["sandbox_then_approval"]
    assert DECISION_RANK["sandbox_then_approval"] < DECISION_RANK["quarantine"]
    assert DECISION_RANK["quarantine"] < DECISION_RANK["block"]


def test_lattice_merges_to_strongest_decision_and_keeps_evidence():
    baseline = PolicyDecision("dec_1", "act_1", "allow", 20, ["base"], [], "ok")
    hits = [
        RuleHit("INV-PARSER-001", "parser", "parser", "sandbox_then_approval", 82, ["low_conf"], ["sandbox"], invariant=True),
        RuleHit("INV-SECRET-001", "secret", "secret", "block", 100, ["secret"], ["block"], evidence_refs=["asset_1"], invariant=True),
    ]
    decision, path = DecisionLattice().merge(baseline, hits)
    assert decision.decision == "block"
    assert decision.risk_score == 100
    assert decision.reason_codes == ["base", "low_conf", "secret"]
    assert "asset_1" in decision.evidence_refs
    assert path[-1]["via"] == "INV-SECRET-001"
