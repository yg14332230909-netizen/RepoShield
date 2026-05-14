import type { JudgmentTraceViewModel } from "../../types";

export function RuleCandidatePruner({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const stats = judgment.skipped_rules_summary || {};
  const total = Number(stats.total_rules || judgment.candidate_rules.length || 0);
  const bySemantic = Number(stats.by_action_semantic || 0);
  const byEvidence = ["by_source_trust", "by_asset_type", "by_package_source", "by_secret_event", "by_contract_match", "by_mcp_capability", "by_sandbox_observation"]
    .reduce((sum, key) => sum + Number(stats[key] || 0), 0);
  const candidates = Number(stats.candidate_rules || judgment.candidate_rules.length || 0);
  const hits = judgment.invariant_hits.length + judgment.predicate_rows.filter((row) => row.matched).length;
  return (
    <section className="judgment-panel rule-pruner">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">RuleIndex</span>
        <h3>证据索引如何剪枝候选规则</h3>
      </div>
      <div className="pruner-steps">
        <PrunerStep label="全部策略规则" value={total} />
        <PrunerStep label="Action semantic 索引命中" value={bySemantic} />
        <PrunerStep label="Evidence facts 索引命中" value={byEvidence} />
        <PrunerStep label="去重后候选规则" value={candidates} />
        <PrunerStep label="最终命中条件" value={hits} />
      </div>
    </section>
  );
}

function PrunerStep({ label, value }: { label: string; value: number }) {
  return <div className="pruner-step"><span>{label}</span><b>{value}</b></div>;
}
