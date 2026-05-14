from pathlib import Path

from reposhield.policy_engine.engine import PolicyGraphEngine
from reposhield.policy_runtime.policy_pack import load_policy_pack, validate_policy_pack


def test_core_coding_agent_yaml_is_loaded_as_policygraph_rules():
    engine = PolicyGraphEngine()
    ids = {rule.rule_id for rule in engine.rule_index.rules}

    assert "RS-SECRET-001" in ids
    assert "RS-SC-001" in ids
    assert "RS-SANDBOX-001" in ids


def test_policygraph_yaml_validates():
    path = Path("src/reposhield/policy_engine/policies/core_coding_agent.yaml")
    data = load_policy_pack(path)
    assert validate_policy_pack(data) == []
