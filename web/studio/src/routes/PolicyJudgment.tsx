import type { JudgmentTraceViewModel, StudioEvent } from "../types";
import { JudgmentWorkspace } from "../components/judgment/JudgmentWorkspace";
import { actionLabel } from "../components/displayText";

export function PolicyJudgment({ judgment, events, onInspectAction }: { judgment: JudgmentTraceViewModel | null; events: StudioEvent[]; onInspectAction: (actionId: string) => void }) {
  const actionEvents = events.filter((event) => event.type === "action_parsed");
  if (!judgment) {
    return (
      <div className="judgment-empty">
        <h3>请选择一个动作查看综合判断过程</h3>
        <p>从时间线、证据图谱或下面的动作列表中点击一个 action，Studio 会展示 Evidence → Facts → Invariants → Rules → Lattice → Decision 的完整链路。</p>
        <div className="judgment-action-list">
          {actionEvents.map((event) => (
            <button key={event.event_id} onClick={() => onInspectAction(String(event.payload.action_id || event.span_id))}>
              <b>{actionLabel(event.payload.semantic_action || event.payload.action_id)}</b>
              <span>{String(event.payload.raw_action || event.summary || "")}</span>
            </button>
          ))}
        </div>
      </div>
    );
  }
  return <JudgmentWorkspace judgment={judgment} />;
}
