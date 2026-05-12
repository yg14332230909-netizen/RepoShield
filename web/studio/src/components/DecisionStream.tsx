import type { StudioEvent } from "../types";
import { DecisionBadge } from "./DecisionBadge";

function decisionOf(event: StudioEvent): string {
  return String(event.payload.decision || event.payload.effective_decision || event.payload.semantic_action || event.type);
}

export function DecisionStream({ events }: { events: StudioEvent[] }) {
  const decisions = events.filter((event) => ["policy_decision", "policy_runtime", "gateway_response"].includes(event.type));
  if (!decisions.length) return <div className="empty-state">No decisions yet.</div>;
  return (
    <div className="decision-stream">
      {decisions.map((event) => (
        <div className="decision-card" key={event.event_id}>
          <DecisionBadge label={decisionOf(event)} severity={event.severity} />
          <b>{event.summary}</b>
          <div className="muted">{Array.isArray(event.payload.reason_codes) ? event.payload.reason_codes.slice(0, 3).join(", ") : ""}</div>
        </div>
      ))}
    </div>
  );
}
