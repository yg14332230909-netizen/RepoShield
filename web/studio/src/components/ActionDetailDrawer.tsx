import type { ActionDetail } from "../types";
import { DecisionBadge } from "./DecisionBadge";

export function ActionDetailDrawer({ detail }: { detail: ActionDetail | null }) {
  if (!detail) return <div className="empty-state">Select an action event to inspect ActionIR, rule trace, source trust and evidence refs.</div>;
  const action = detail.action;
  const decision = detail.decision;
  const label = String(decision.decision || detail.runtime.effective_decision || "unknown");
  return (
    <div id="action-detail">
      <section className="detail-section">
        <h3>{String(action.semantic_action || detail.action_id)}</h3>
        <DecisionBadge label={label} severity={label === "block" ? "critical" : "warning"} />
      </section>
      <section className="detail-section"><h3>Raw Action</h3><pre>{String(action.raw_action || "")}</pre></section>
      <section className="detail-section"><h3>Source Trust</h3><pre>{JSON.stringify(detail.sources, null, 2)}</pre></section>
      <section className="detail-section"><h3>Matched Rules</h3><pre>{JSON.stringify(decision.matched_rules || [], null, 2)}</pre></section>
      <section className="detail-section"><h3>Rule Trace</h3><pre>{JSON.stringify(decision.rule_trace || [], null, 2)}</pre></section>
      <section className="detail-section"><h3>Evidence Refs</h3><pre>{JSON.stringify(decision.evidence_refs || [], null, 2)}</pre></section>
      <section className="detail-section"><h3>ActionIR</h3><pre>{JSON.stringify(action, null, 2)}</pre></section>
    </div>
  );
}
