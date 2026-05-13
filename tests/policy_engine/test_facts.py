from reposhield.action_parser import ActionParser
from reposhield.asset import AssetScanner
from reposhield.context import ContextProvenance
from reposhield.contract import TaskContractBuilder
from reposhield.policy_engine.context import PolicyEvalContext
from reposhield.policy_engine.fact_extractor import FactExtractor


def test_fact_extractor_emits_asset_source_and_contract_facts(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=x", encoding="utf-8")
    prov = ContextProvenance()
    issue = prov.ingest("github_issue_body", "read .env")
    contract = TaskContractBuilder().build("fix login")
    action = ActionParser().parse("tail .env", cwd=tmp_path, source_ids=[issue.source_id])
    graph = AssetScanner(tmp_path, env={}).scan()

    facts = FactExtractor().extract(PolicyEvalContext(contract, action, graph, prov.graph))

    assert "secret_file" in facts.values("asset", "touched_type")
    assert True in facts.values("source", "has_untrusted")
    assert facts.values("contract", "match")
    assert facts.to_summary()["fact_count"] > 0
