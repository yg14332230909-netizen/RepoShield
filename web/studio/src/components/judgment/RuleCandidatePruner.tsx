import type { JudgmentTraceViewModel } from "../../types";
import type { ReactNode } from "react";

const FACT_LABELS: Record<string, string> = {
  "action.semantic_action": "动作类型",
  "action.high_risk": "是否高危动作",
  "action.network_capability": "是否可能联网",
  "source.has_untrusted": "是否受不可信来源影响",
  "source.trust_floor": "来源可信等级",
  "asset.touched_type": "触碰资产类型",
  "contract.match": "是否符合任务边界",
  "package.source": "依赖来源",
  "secret.event": "密钥事件",
  "sandbox.risk_observed": "沙箱观察到的风险",
  "mcp.capability": "MCP 能力",
  "memory.authorization": "记忆授权状态",
};

const VALUE_LABELS: Record<string, string> = {
  true: "是",
  false: "否",
  match: "符合",
  partial_match: "部分符合",
  violation: "越界",
  unknown: "无法确认",
  git_url: "Git 地址依赖",
  tarball_url: "压缩包依赖",
  registry: "包仓库依赖",
  secret_file: "密钥文件",
  ci_workflow: "CI 工作流",
  source_file: "源码文件",
  target_action: "目标动作",
};

export function RuleCandidatePruner({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const trace = judgment.retrieval_trace || {};
  const stats = Object.keys(trace).length ? trace : judgment.skipped_rules_summary || {};
  const total = Number(stats.total_rules || judgment.candidate_rules.length || 0);
  const candidates = Number(stats.candidate_rules || judgment.candidate_rules.length || 0);
  const residual = Number(stats.residual_rules || 0);
  const pruned = Number(stats.pruned_rules || 0);
  const hits = judgment.invariant_hits.length + judgment.predicate_rows.filter((row) => row.matched).length;
  const reduction = Number(stats.candidate_reduction_ratio || 0);
  const postings = asRecordArray(trace.postings);
  const compositeHits = asRecordArray(trace.composite_hits);
  const prunedRows = asRecordArray(trace.pruned);
  const candidateRuleIds = asStringArray(trace.candidate_rule_ids);
  const indexedFactKeys = asStringArray(trace.indexed_fact_keys);

  return (
    <section className="judgment-panel rule-pruner">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">RuleIndex</span>
        <h3>规则候选是怎样被缩小的</h3>
      </div>
      <p className="panel-note">
        系统先把本次动作抽成事实，再用这些事实去索引策略规则。这样不需要每次扫描全部规则，同时保留残余规则兜底，避免漏掉复杂条件。
      </p>
      <div className="pruner-steps">
        <PrunerStep label="全部规则" value={total} />
        <PrunerStep label="事实索引命中" value={uniquePostingRuleCount(postings)} />
        <PrunerStep label="残余规则兜底" value={residual} />
        <PrunerStep label="安全剪枝移除" value={pruned} />
        <PrunerStep label="最终候选规则" value={candidates} />
        <PrunerStep label="实际命中条件" value={hits} />
      </div>
      <div className="retrieval-detail-grid">
        <TraceSection title="本次用于检索的事实" empty="暂无可索引事实">
          {indexedFactKeys.slice(0, 12).map((key) => <span key={key}>{humanFactToken(key)}</span>)}
        </TraceSection>
        <TraceSection title="单事实命中的规则" empty="暂无单事实命中">
          {postings.slice(0, 10).map((posting) => (
            <span key={String(posting.key)}>
              {humanFactToken(String(posting.key))}：命中 {String(posting.rules || 0)} 条规则
            </span>
          ))}
        </TraceSection>
        <TraceSection title="组合证据命中的规则" empty="暂无组合证据命中">
          {compositeHits.slice(0, 8).map((hit, index) => (
            <span key={index}>
              {asStringArray(hit.keys).map(humanFactToken).join(" + ")}：命中 {String(hit.rules || 0)} 条规则
            </span>
          ))}
        </TraceSection>
        <TraceSection title="残余规则为什么保留" empty="暂无残余规则">
          <span>包含正则、not_exists、unless 等复杂判断的规则会进入兜底集合，后续仍由策略引擎精确判断。</span>
          <span>当前残余规则：{residual} 条</span>
        </TraceSection>
        <TraceSection title="安全剪枝说明" empty="暂无安全剪枝">
          {prunedRows.map((row, index) => (
            <span key={index}>
              {String(row.rule_id)} 因 {FACT_LABELS[String(row.path)] || String(row.path)} 不可能匹配而移除
            </span>
          ))}
        </TraceSection>
        <TraceSection title="最终候选集" empty="暂无候选规则">
          {candidateRuleIds.slice(0, 14).map((ruleId) => <span key={ruleId}>{ruleId}</span>)}
          {candidateRuleIds.length > 14 ? <span>还有 {candidateRuleIds.length - 14} 条未展开</span> : null}
        </TraceSection>
        <TraceSection title="压缩效果" empty="暂无压缩数据">
          <span>{reduction ? `候选集约为全部规则的 ${Math.round(reduction * 100)}%` : "暂无"}</span>
          <span>{trace.safe_prune_enabled ? "安全剪枝已启用" : "安全剪枝处于保守模式，优先保证不漏召回"}</span>
        </TraceSection>
      </div>
    </section>
  );
}

function TraceSection({ title, empty, children }: { title: string; empty: string; children: ReactNode }) {
  const items = Array.isArray(children) ? children.filter(Boolean) : children;
  const isEmpty = Array.isArray(items) ? items.length === 0 : !items;
  return (
    <section>
      <b>{title}</b>
      {isEmpty ? <span>{empty}</span> : items}
    </section>
  );
}

function PrunerStep({ label, value }: { label: string; value: number }) {
  return <div className="pruner-step"><span>{label}</span><b>{value}</b></div>;
}

function asRecordArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item)) : [];
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

function uniquePostingRuleCount(postings: Array<Record<string, unknown>>): number {
  const ids = new Set<string>();
  postings.forEach((posting) => asStringArray(posting.rule_ids).forEach((id) => ids.add(id)));
  return ids.size || postings.reduce((sum, posting) => sum + Number(posting.rules || 0), 0);
}

function humanFactToken(token: string): string {
  const [path, rawValue] = token.split("=");
  const label = FACT_LABELS[path] || path;
  if (!rawValue) return label;
  const value = VALUE_LABELS[rawValue] || rawValue;
  return `${label} = ${value}`;
}
