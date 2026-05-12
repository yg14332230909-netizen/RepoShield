import type { StudioEvent } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";

export function PolicyDebugger({ events }: { events: StudioEvent[] }) {
  const decisions = events.filter((event) => event.type === "policy_decision");
  return (
    <div className="rule-stack">
      {decisions.map((event) => {
        const payload = event.payload;
        return (
          <div className="rule-card" key={event.event_id}>
            <DecisionBadge label={String(payload.decision || "decision")} severity={event.severity} />
            <h3>{String(payload.semantic_action || payload.action_id || "action")}</h3>
            <p className="muted">{String(payload.explanation || "")}</p>
            <pre>{JSON.stringify({ matched_rules: payload.matched_rules, evidence_refs: payload.evidence_refs, rule_trace: payload.rule_trace }, null, 2)}</pre>
          </div>
        );
      })}
    </div>
  );
}
