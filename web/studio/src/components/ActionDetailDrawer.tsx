import type { ActionDetail } from "../types";
import { DecisionBadge, displayLabel } from "./DecisionBadge";
import { actionLabel, reasonLabels, shortId } from "./displayText";
import { factSetFromEvents, PolicyTraceDebugger, predicatesFromTrace, traceFromEvents } from "./PolicyTraceDebugger";

function sourcesText(sources: Array<Record<string, unknown>>): string {
  if (!sources.length) return "没有外部来源影响";
  return sources.map((source) => {
    const id = String(source.source_id || "来源");
    const trust = displayLabel(String(source.trust_level || source.trust || "unknown"));
    return `${shortId(id)}（${trust}）`;
  }).join("、");
}

function ruleNames(decision: Record<string, unknown>): string[] {
  const rules = Array.isArray(decision.matched_rules) ? decision.matched_rules as Array<Record<string, unknown>> : [];
  return rules.map((rule) => {
    const id = String(rule.rule_id || rule.name || "");
    if (id.includes("SECRET")) return "密钥保护规则";
    if (id.includes("SANDBOX")) return "沙箱约束规则";
    if (id.includes("PACKAGE")) return "依赖安全规则";
    if (id.includes("CI")) return "发布流程保护规则";
    return String(rule.name || rule.rule_id || "策略规则");
  });
}

export function ActionDetailDrawer({ detail, onOpenJudgment }: { detail: ActionDetail | null; onOpenJudgment?: () => void }) {
  if (!detail) return (
    <div className="action-empty-state">
      <h3>还没有选中具体动作</h3>
      <p>在“本次运行”的时间线里点击“识别到动作”卡片，右侧会显示 RepoShield 如何理解这条工具调用。</p>
      <p>这里适合回答：代理原本想做什么、被识别成什么风险动作、为什么危险、证据在哪里。</p>
    </div>
  );
  const action = detail.action;
  const decision = detail.decision;
  const label = String(decision.decision || detail.runtime.effective_decision || "unknown");
  const semanticAction = actionLabel(action.semantic_action || detail.action_id);
  const reasons = reasonLabels(decision.reason_codes);
  const rules = ruleNames(decision);
  const trace = detail.policy_eval_trace || traceFromEvents(detail.evidence_events, detail.action_id);
  const factSet = detail.policy_fact_set || factSetFromEvents(detail.evidence_events, detail.action_id, trace?.policy_eval_trace_id);
  const predicates = detail.policy_predicates?.length ? detail.policy_predicates : predicatesFromTrace(trace);
  return (
    <div id="action-detail" className="action-detail-view">
      <section className="action-summary-card">
        <div>
          <span className="policy-eyebrow">RepoShield 识别到的动作</span>
          <h3>{semanticAction}</h3>
          <p>{label === "block" ? "这个动作被判定为不能执行。" : "这个动作需要受限执行或进一步确认。"}</p>
        </div>
        <DecisionBadge label={label} severity={label === "block" ? "critical" : "warning"} />
      </section>
      <section className="action-readable-grid">
        <div><b>代理原本想做什么</b><code>{String(action.raw_action || "没有原始命令")}</code></div>
        <div><b>为什么危险</b><span>{reasons.length ? reasons.join("、") : "没有额外原因码"}</span></div>
        <div><b>来源影响</b><span>{sourcesText(detail.sources)}</span></div>
        <div><b>命中规则</b><span>{rules.length ? rules.join("、") : "没有规则明细"}</span></div>
      </section>
      <button className="primary judgment-open-button" onClick={onOpenJudgment}>打开综合判断过程</button>
      <PolicyTraceDebugger
        trace={trace}
        predicates={predicates}
        factSet={factSet}
        decision={decision}
        action={action}
        title="动作级 Policy Debugger"
        compact
      />
      <details className="raw-graph">
        <summary>查看取证细节</summary>
        <section className="detail-section"><h3>来源信任</h3><pre>{JSON.stringify(detail.sources, null, 2)}</pre></section>
        <section className="detail-section"><h3>规则轨迹</h3><pre>{JSON.stringify(decision.rule_trace || [], null, 2)}</pre></section>
        <section className="detail-section"><h3>证据引用</h3><pre>{JSON.stringify(decision.evidence_refs || [], null, 2)}</pre></section>
        <section className="detail-section"><h3>结构化动作原文</h3><pre>{JSON.stringify(action, null, 2)}</pre></section>
      </details>
    </div>
  );
}
