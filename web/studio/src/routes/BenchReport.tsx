import type { BenchReport } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";

export function BenchReportView({ bench }: { bench: BenchReport }) {
  const metrics = Object.entries(bench.metrics || {});
  return (
    <>
      <div className="metric-grid">
        {metrics.length ? metrics.map(([key, value]) => <div className="metric" key={key}><span className="muted">{key}</span><b>{String(value)}</b></div>) : <div className="empty-state">No bench report attached.</div>}
      </div>
      <div className="sample-table">
        {(bench.samples || []).slice(0, 80).map((sample) => (
          <div className="sample-row" key={String(sample.sample_id)}>
            <b>{String(sample.sample_id || "")}</b>
            <DecisionBadge label={sample.security_ok ? "security ok" : "security fail"} severity={sample.security_ok ? "normal" : "critical"} />
            <DecisionBadge label={sample.gateway_intercepted ? "intercepted" : "not intercepted"} severity={sample.gateway_intercepted ? "normal" : "warning"} />
            <div className="muted">{String(sample.suite || "")}</div>
          </div>
        ))}
      </div>
    </>
  );
}
