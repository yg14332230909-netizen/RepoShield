import type { StudioEvent } from "../types";
import { DecisionBadge, displayLabel } from "../components/DecisionBadge";

export function PolicyDebugger({ events }: { events: StudioEvent[] }) {
  const decisions = events.filter((event) => event.type === "policy_decision");
  const conditionRows = decisions.flatMap((event) => {
    const payload = event.payload;
    const traces = Array.isArray(payload.rule_trace) ? payload.rule_trace : [];
    return traces.map((trace, index) => {
      const item = trace as Record<string, unknown>;
      return {
        id: `${event.event_id}-${index}`,
        action: String(item.semantic_action || payload.semantic_action || payload.action_id || "action"),
        risk: String(item.risk || ""),
        sourceIds: Array.isArray(item.source_ids) ? item.source_ids.join(", ") : "",
        reasons: Array.isArray(item.reason_codes) ? item.reason_codes.join(", ") : "",
        decision: String(item.decision || payload.decision || "decision"),
        severity: event.severity,
      };
    });
  });
  return (
    <>
      <div className="rule-matrix">
        <div className="rule-matrix-head">条件</div><div className="rule-matrix-head">观测结果</div><div className="rule-matrix-head">证据</div><div className="rule-matrix-head">决策</div>
        {conditionRows.map((row) => (
          <>
            <div key={`${row.id}-condition`}>{row.action} / {row.risk}</div>
            <div key={`${row.id}-observed`}>{row.reasons || "已命中"}</div>
            <div key={`${row.id}-evidence`}>{row.sourceIds || "策略证据"}</div>
            <div key={`${row.id}-decision`}><DecisionBadge label={row.decision} severity={row.severity} /></div>
          </>
        ))}
      </div>
      <div className="rule-stack">
      {decisions.map((event) => {
        const payload = event.payload;
        return (
          <div className="rule-card" key={event.event_id}>
            <DecisionBadge label={String(payload.decision || "decision")} severity={event.severity} />
            <h3>{displayLabel(String(payload.semantic_action || payload.action_id || "action"))}</h3>
            <p className="muted">{String(payload.explanation || "")}</p>
            <pre>{JSON.stringify({ matched_rules: payload.matched_rules, evidence_refs: payload.evidence_refs, rule_trace: payload.rule_trace }, null, 2)}</pre>
          </div>
        );
      })}
      </div>
    </>
  );
}
