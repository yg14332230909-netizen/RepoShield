from reposhield.action_parser import ActionParser
from reposhield.asset import AssetScanner
from reposhield.context import ContextProvenance
from reposhield.contract import TaskContractBuilder
from reposhield.models import PolicyDecision
from reposhield.policy import PolicyEngine
from reposhield.policy_config import ConfigurablePolicyOverrides


def test_policygraph_is_the_only_engine_and_records_eval_trace(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=x", encoding="utf-8")
    contract = TaskContractBuilder().build("fix login")
    graph = AssetScanner(tmp_path, env={}).scan()
    action = ActionParser().parse("tail .env", cwd=tmp_path)
    action.semantic_action = "read_project_file"
    engine = PolicyEngine(mode="legacy")

    decision = engine.decide(contract, action, graph, ContextProvenance().graph)
    events = engine.consume_eval_events()

    assert decision.decision == "block"
    assert decision.policy_version == "reposhield-policygraph-v0.4"
    assert events
    assert events[-1]["engine_mode"] == "policygraph-enforce"
    assert events[-1]["invariant_hits"] == ["INV-SECRET-001"]


def test_invariant_decision_cannot_be_downgraded_by_admin_signed_override():
    decision = PolicyDecision(
        "dec_1",
        "act_1",
        "block",
        100,
        ["secret_asset_touched"],
        ["block"],
        "blocked",
        matched_rules=[{"rule_id": "INV-SECRET-001", "invariant": True}],
        rule_trace=[{"invariant_hits": ["INV-SECRET-001"]}],
    )
    overrides = ConfigurablePolicyOverrides([
        {
            "name": "try_allow_secret",
            "match": {"decision": "block"},
            "decision": "allow",
            "unsafe_override": True,
            "admin_signed": True,
        }
    ])

    updated = overrides.apply(ActionParser().parse("cat .env"), decision)

    assert updated.decision == "block"
    assert "invariant_policy_downgrade_rejected" in updated.reason_codes
