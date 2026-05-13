import type { ApprovalEvent } from "../types";
import { DecisionBadge, displayLabel } from "../components/DecisionBadge";

function statusFor(request: ApprovalEvent, events: ApprovalEvent[]): "pending" | "granted" | "denied" {
  const payload = request.payload;
  const requestId = String(payload.approval_request_id || "");
  if (events.some((event) => event.event_type === "denial" && event.payload.approval_request_id === requestId)) return "denied";
  if (events.some((event) => event.event_type === "grant" && event.payload.action_id === payload.action_id && event.payload.approved_action_hash === payload.action_hash)) return "granted";
  return "pending";
}

export function ApprovalCenter({ events, onGrant, onDeny }: { events: ApprovalEvent[]; onGrant: (approvalId: string, actionHash: string) => void; onDeny: (approvalId: string) => void }) {
  const requests = events.filter((event) => event.event_type === "request").reverse();
  if (!requests.length) return <div className="empty-state">暂无审批请求。</div>;
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
            <div className="hash-summary">
              <b>哈希绑定摘要</b>
              <span>task_id={String(payload.task_id || "无")}</span>
              <span>action_id={String(payload.action_id || "无")}</span>
              <span>plan_hash={String(payload.plan_hash || "无")}</span>
              <span>affected_assets={JSON.stringify(payload.affected_assets || [])}</span>
            </div>
            {status === "pending" ? (
              <>
                <button className="primary" onClick={() => {
                  const ok = window.confirm(`确认仅以 sandbox-only 方式批准这个精确动作吗？\n\n${String(payload.human_readable_summary || approvalId)}\n\naction_hash=${actionHash}`);
                  if (ok) onGrant(approvalId, actionHash);
                }}>批准 sandbox-only</button>
                <button className="danger" onClick={() => {
                  const ok = window.confirm(`确认拒绝审批请求 ${approvalId} 吗？`);
                  if (ok) onDeny(approvalId);
                }}>拒绝</button>
              </>
            ) : <div className="muted">该请求已在 ApprovalStore 中结束，状态为 {displayLabel(status)}。</div>}
          </div>
        );
      })}
    </div>
  );
}
