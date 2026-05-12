import type { BenchReport } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";
import { useMemo, useState } from "react";

export function BenchReportView({ bench }: { bench: BenchReport }) {
  const [suite, setSuite] = useState("");
  const [security, setSecurity] = useState("");
  const metrics = Object.entries(bench.metrics || {});
  const samples = bench.samples || [];
  const suites = useMemo(() => Array.from(new Set(samples.map((sample) => String(sample.suite || "")).filter(Boolean))).sort(), [samples]);
  const visible = samples.filter((sample) => {
    if (suite && sample.suite !== suite) return false;
    if (security === "ok" && !sample.security_ok) return false;
    if (security === "fail" && sample.security_ok) return false;
    return true;
  });
  return (
    <>
      <div className="metric-grid">
        {metrics.length ? metrics.map(([key, value]) => <div className="metric" key={key}><span className="muted">{key}</span><b>{String(value)}</b></div>) : <div className="empty-state">未附加评测报告。</div>}
      </div>
      <div className="bench-filters">
        <label>样本集
          <select value={suite} onChange={(event) => setSuite(event.target.value)}>
            <option value="">全部样本集</option>
            {suites.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label>安全结果
          <select value={security} onChange={(event) => setSecurity(event.target.value)}>
            <option value="">全部结果</option>
            <option value="ok">安全通过</option>
            <option value="fail">安全失败</option>
          </select>
        </label>
        <span className="status-pill">{visible.length} 个样本</span>
      </div>
      <div className="sample-table">
        {visible.slice(0, 120).map((sample) => (
          <div className="sample-row" key={String(sample.sample_id)}>
            <b>{String(sample.sample_id || "")}</b>
            <DecisionBadge label={sample.security_ok ? "安全通过" : "安全失败"} severity={sample.security_ok ? "normal" : "critical"} />
            <DecisionBadge label={sample.gateway_intercepted ? "已拦截" : "未拦截"} severity={sample.gateway_intercepted ? "normal" : "warning"} />
            <div className="muted">{String(sample.suite || "")} · dangerous executed={String(sample.dangerous_action_executed ?? "n/a")}</div>
          </div>
        ))}
      </div>
    </>
  );
}
