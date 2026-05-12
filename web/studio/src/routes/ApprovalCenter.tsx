import type { ApprovalEvent } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";

function statusFor(request: ApprovalEvent, events: ApprovalEvent[]): "pending" | "granted" | "denied" {
  const payload = request.payload;
  const requestId = String(payload.approval_request_id || "");
  if (events.some((event) => event.event_type === "denial" && event.payload.approval_request_id === requestId)) return "denied";
  if (events.some((event) => event.event_type === "grant" && event.payload.action_id === payload.action_id && event.payload.approved_action_hash === payload.action_hash)) return "granted";
  return "pending";
}

export function ApprovalCenter({ events, onGrant, onDeny }: { events: ApprovalEvent[]; onGrant: (approvalId: string, actionHash: string) => void; onDeny: (approvalId: string) => void }) {
  const requests = events.filter((event) => event.event_type === "request").reverse();
  if (!requests.length) return <div className="empty-state">No approval requests.</div>;
  return (
    <div className="approval-list">
      {requests.map((event) => {
        const payload = event.payload;
        const approvalId = String(payload.approval_request_id || "");
        const actionHash = String(payload.action_hash || "");
        const status = statusFor(event, events);
        return (
          <div className="approval-card" key={approvalId}>
            <DecisionBadge label={status} severity={status === "pending" ? "warning" : status === "granted" ? "normal" : "critical"} />
            <h3>{String(payload.human_readable_summary || approvalId)}</h3>
            <div className="kv">
              <span>approval_id</span><span>{approvalId}</span>
              <span>action_hash</span><span>{actionHash}</span>
              <span>source</span><span>{JSON.stringify(payload.source_influence || [])}</span>
            </div>
            {status === "pending" ? (
              <>
                <button className="primary" onClick={() => onGrant(approvalId, actionHash)}>Grant sandbox-only</button>
                <button className="danger" onClick={() => onDeny(approvalId)}>Deny</button>
              </>
            ) : <div className="muted">Finalized in ApprovalStore as {status}.</div>}
          </div>
        );
      })}
    </div>
  );
}
