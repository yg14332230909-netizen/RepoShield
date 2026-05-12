import type { RunSummary, StudioEvent } from "../types";
import { LiveTimeline } from "../components/LiveTimeline";

export function RunCockpit({ run, events, criticalOnly, setCriticalOnly, onInspectAction }: { run: RunSummary | null; events: StudioEvent[]; criticalOnly: boolean; setCriticalOnly: (value: boolean) => void; onInspectAction: (actionId: string) => void }) {
  const metrics = [
    ["Events", run?.event_count || 0],
    ["Actions", run?.action_count || 0],
    ["Blocked", run?.blocked_count || 0],
    ["Approvals", run?.approval_count || 0],
    ["Critical", run?.critical_count || 0],
    ["Latest", run?.latest_decision || "observing"]
  ];
  return (
    <>
      <div className="metric-grid">{metrics.map(([label, value]) => <div className="metric" key={label}><span className="muted">{label}</span><b>{value}</b></div>)}</div>
      <div className="panel-head inline">
        <h3>Live Timeline</h3>
        <label><input type="checkbox" checked={criticalOnly} onChange={(e) => setCriticalOnly(e.target.checked)} /> Critical only</label>
      </div>
      <LiveTimeline events={events} criticalOnly={criticalOnly} onInspectAction={onInspectAction} />
    </>
  );
}
