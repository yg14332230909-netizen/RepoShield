import type { ActionDetail } from "../types";
import { DecisionBadge } from "./DecisionBadge";

export function ActionDetailDrawer({ detail }: { detail: ActionDetail | null }) {
  if (!detail) return <div className="empty-state">选择一个动作事件，即可查看 ActionIR、规则轨迹、来源信任级别和证据引用。</div>;
  const action = detail.action;
  const decision = detail.decision;
  const label = String(decision.decision || detail.runtime.effective_decision || "unknown");
  return (
    <div id="action-detail">
      <section className="detail-section">
        <h3>{String(action.semantic_action || detail.action_id)}</h3>
        <DecisionBadge label={label} severity={label === "block" ? "critical" : "warning"} />
      </section>
      <section className="detail-section"><h3>原始动作</h3><pre>{String(action.raw_action || "")}</pre></section>
      <section className="detail-section"><h3>来源信任</h3><pre>{JSON.stringify(detail.sources, null, 2)}</pre></section>
      <section className="detail-section"><h3>命中规则</h3><pre>{JSON.stringify(decision.matched_rules || [], null, 2)}</pre></section>
      <section className="detail-section"><h3>规则轨迹</h3><pre>{JSON.stringify(decision.rule_trace || [], null, 2)}</pre></section>
      <section className="detail-section"><h3>证据引用</h3><pre>{JSON.stringify(decision.evidence_refs || [], null, 2)}</pre></section>
      <section className="detail-section"><h3>ActionIR</h3><pre>{JSON.stringify(action, null, 2)}</pre></section>
    </div>
  );
}
