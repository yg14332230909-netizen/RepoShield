import type { StudioEvent } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";

export function SandboxEvidence({ events }: { events: StudioEvent[] }) {
  const traces = events.filter((event) => event.type === "exec_trace");
  if (!traces.length) return <div className="empty-state">当前运行暂无沙箱预检证据。</div>;
  return (
    <div className="evidence-grid">
      {traces.map((event) => {
        const payload = event.payload;
        const networkAttempts = Array.isArray(payload.network_attempts) ? payload.network_attempts : [];
        const filesRead = Array.isArray(payload.files_read) ? payload.files_read : [];
        const filesWritten = Array.isArray(payload.files_written) ? payload.files_written : [];
        const processTree = Array.isArray(payload.process_tree) ? payload.process_tree : [];
        const diffSummary = Array.isArray(payload.diff_summary) ? payload.diff_summary : [];
        return (
          <div className="sandbox-card" key={event.event_id}>
            <DecisionBadge label={String(payload.recommended_decision || "sandbox")} severity={event.severity} />
            <h3>{String(payload.command || event.summary)}</h3>
            <div className="sandbox-grid">
              <div><b>沙箱配置</b><span>{String(payload.sandbox_profile || "n/a")}</span></div>
              <div><b>网络意图</b><span>{networkAttempts.length} 次尝试</span></div>
              <div><b>文件访问</b><span>{filesRead.length} 读 / {filesWritten.length} 写</span></div>
              <div><b>观测风险</b><span>{Array.isArray(payload.risk_observed) ? payload.risk_observed.join(", ") : "none"}</span></div>
            </div>
            <div className="sandbox-columns">
              <section><h4>进程树</h4><pre>{JSON.stringify(processTree, null, 2)}</pre></section>
              <section><h4>网络意图</h4><pre>{JSON.stringify(networkAttempts, null, 2)}</pre></section>
              <section><h4>文件差异</h4><pre>{JSON.stringify({ files_read: filesRead, files_written: filesWritten, diff_summary: diffSummary }, null, 2)}</pre></section>
              <section><h4>脱敏原始 trace</h4><pre>{JSON.stringify(payload, null, 2)}</pre></section>
            </div>
          </div>
        );
      })}
    </div>
  );
}
