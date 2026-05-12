import type { StudioEvent } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";

export function SandboxEvidence({ events }: { events: StudioEvent[] }) {
  const traces = events.filter((event) => event.type === "exec_trace");
  if (!traces.length) return <div className="empty-state">No sandbox preflight evidence for this run.</div>;
  return (
    <div className="evidence-grid">
      {traces.map((event) => {
        const payload = event.payload;
        return (
          <div className="sandbox-card" key={event.event_id}>
            <DecisionBadge label={String(payload.recommended_decision || "sandbox")} severity={event.severity} />
            <h3>{String(payload.command || event.summary)}</h3>
            <div className="kv">
              <span>profile</span><span>{String(payload.sandbox_profile || "n/a")}</span>
              <span>network</span><span>{String(Array.isArray(payload.network_attempts) ? payload.network_attempts.length : 0)}</span>
              <span>risk</span><span>{Array.isArray(payload.risk_observed) ? payload.risk_observed.join(", ") : "none"}</span>
            </div>
            <pre>{JSON.stringify(payload, null, 2)}</pre>
          </div>
        );
      })}
    </div>
  );
}
