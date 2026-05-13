import type { StudioEvent } from "../types";
import { DecisionBadge, displayLabel } from "../components/DecisionBadge";
import { actionLabel, reasonLabels } from "../components/displayText";

function decisionEvents(events: StudioEvent[]): StudioEvent[] {
  return events.filter((event) => event.type === "policy_decision");
}

function explainDecision(decision: string): string {
  if (decision === "block") return "这个动作不能执行，因为它越过了用户授权边界或触碰了高危资产。";
  if (decision === "allow_in_sandbox") return "这个动作可以执行，但必须限制在沙箱中，避免影响真实仓库或外部环境。";
  if (decision === "sandbox_then_approval") return "这个动作需要先沙箱预检，再交给人确认。";
  if (decision === "allow") return "这个动作符合任务边界，可以继续执行。";
  return "策略引擎根据动作、来源和证据给出了当前结论。";
}

function sourceLabel(sourceIds: unknown): string {
  if (!Array.isArray(sourceIds) || !sourceIds.length) return "没有外部来源影响";
  return sourceIds.map((item) => String(item).replace("src_attack_secret_exfil", "攻击 Issue").replace("src_attack_ci_poison", "可疑 PR 评论").replace("src_attack_dependency_confusion", "可疑 Issue")).join("、");
}

function evidenceLabel(value: unknown): string[] {
  if (!Array.isArray(value) || !value.length) return ["策略规则本身"];
  return value.map((item) => {
    const raw = String(item);
    if (raw.startsWith("trace_")) return "沙箱预检结果";
    if (raw.startsWith("src_attack")) return "不可信外部文本";
    return raw;
  });
}

function ruleName(rule: Record<string, unknown>): string {
  const id = String(rule.rule_id || rule.name || "");
  if (id.includes("SECRET")) return "密钥保护规则";
  if (id.includes("SANDBOX")) return "沙箱约束规则";
  if (id.includes("PACKAGE")) return "依赖安全规则";
  if (id.includes("CI")) return "发布流程保护规则";
  return String(rule.name || rule.rule_id || "策略规则");
}

export function PolicyDebugger({ events }: { events: StudioEvent[] }) {
  const decisions = decisionEvents(events);
  if (!decisions.length) return <div className="empty-state">当前运行还没有策略决策。运行一个场景后，这里会解释每个动作为什么被放行、沙箱、审批或阻断。</div>;
  return (
    <div className="policy-debugger">
      <div className="policy-explainer">
        <b>策略调试看什么？</b>
        <span>这里把“动作是什么、为什么危险、命中了哪条规则、证据来自哪里”拆开说明，帮助判断这是合理拦截还是误报。</span>
      </div>
      {decisions.map((event) => {
        const payload = event.payload;
        const decision = String(payload.decision || "decision");
        const action = actionLabel(payload.semantic_action || payload.action_id);
        const reasons = reasonLabels(payload.reason_codes);
        const matchedRules = Array.isArray(payload.matched_rules) ? payload.matched_rules as Record<string, unknown>[] : [];
        const traces = Array.isArray(payload.rule_trace) ? payload.rule_trace as Record<string, unknown>[] : [];
        const sourceIds = traces.flatMap((trace) => Array.isArray(trace.source_ids) ? trace.source_ids : []);
        return (
          <div className={`policy-card ${event.severity}`} key={event.event_id}>
            <div className="policy-card-head">
              <div>
                <span className="policy-eyebrow">策略结论</span>
                <h3>{displayLabel(decision)}：{action}</h3>
                <p>{explainDecision(decision)}</p>
              </div>
              <DecisionBadge label={decision} severity={event.severity} />
            </div>

            <div className="policy-summary-grid">
              <section>
                <b>1. 代理想做什么</b>
                <span>{action}</span>
                <small>风险级别：{displayLabel(String(traces[0]?.risk || "unknown"))}</small>
              </section>
              <section>
                <b>2. 为什么触发策略</b>
                <div className="reason-list">
                  {(reasons.length ? reasons : ["策略规则已命中"]).map((reason) => <span key={reason}>{reason}</span>)}
                </div>
              </section>
              <section>
                <b>3. 证据来自哪里</b>
                <span>{sourceLabel(sourceIds)}</span>
                <small>{evidenceLabel(payload.evidence_refs).join("、")}</small>
              </section>
            </div>

            <div className="matched-rule-list">
              <b>命中的规则</b>
              {matchedRules.length ? matchedRules.map((rule, index) => (
                <div className="matched-rule" key={`${event.event_id}-${index}`}>
                  <span>{ruleName(rule)}</span>
                  <DecisionBadge label={String(rule.decision || decision)} severity={event.severity} />
                </div>
              )) : <span className="muted">没有额外规则明细。</span>}
            </div>

            <details className="raw-graph">
              <summary>查看原始策略轨迹</summary>
              <pre>{JSON.stringify({ matched_rules: payload.matched_rules, evidence_refs: payload.evidence_refs, rule_trace: payload.rule_trace }, null, 2)}</pre>
            </details>
          </div>
        );
      })}
    </div>
  );
}
