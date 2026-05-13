import { useState } from "react";
import { ActionDetailDrawer } from "../components/ActionDetailDrawer";
import { DecisionBadge } from "../components/DecisionBadge";
import { DecisionStream } from "../components/DecisionStream";
import { TokenControl } from "../components/TokenControl";
import { ApprovalCenter } from "../routes/ApprovalCenter";
import { AttackLab } from "../routes/AttackLab";
import { BenchReportView } from "../routes/BenchReport";
import { RunCockpit } from "../routes/RunCockpit";
import { SandboxEvidence } from "../routes/SandboxEvidence";
import { TraceGraph } from "../routes/TraceGraph";
import { PolicyDebugger } from "../routes/PolicyDebugger";
import { useRunStore } from "../state/useRunStore";

type Tab = "cockpit" | "attack" | "graph" | "policy" | "approvals" | "sandbox" | "bench";

export function App() {
  const store = useRunStore();
  const [criticalOnly, setCriticalOnly] = useState(false);
  const [tab, setTab] = useState<Tab>("cockpit");
  const mode = store.health ? (store.health.demo_mode ? "演示模式" : "实时模式") : "连接中";

  async function refreshAll() {
    await store.refreshRuns();
    await store.refreshSecondary();
  }

  async function exportEvidence() {
    const output = await store.exportEvidence();
    if (output) window.alert(`证据包已导出到 ${output}`);
  }

  return (
    <>
      <header className="topbar">
        <div><h1>RepoShield Studio Pro</h1><p>面向 coding agent 网关运行态、攻击链和策略决策的实时观测控制台。</p></div>
        <div className="topbar-actions">
          <span className="status-pill">{store.health?.version || "等待服务"} · {mode}</span>
          <TokenControl />
          <button onClick={refreshAll}>刷新</button>
        </div>
      </header>
      <main className="shell">
        <aside className="sidebar">
          <div className="panel-head"><h2>运行记录</h2><span className="muted">{store.runs.length}</span></div>
          <div className="run-list">
            {store.runs.map((run) => (
              <button key={run.run_id} className={`run-card ${run.run_id === store.selectedRunId ? "active" : ""}`} onClick={() => store.selectRun(run.run_id)}>
                <b>{run.demo_scenario_id || run.run_id}</b>
                <div className="muted">{run.event_count} 个事件 · {run.action_count} 个动作</div>
                <DecisionBadge label={run.latest_decision || "observing"} severity={run.blocked_count ? "critical" : "normal"} />
              </button>
            ))}
          </div>
        </aside>
        <section className="workspace">
          <nav className="tabs" aria-label="Studio 分区">
            {[
              ["cockpit", "运行驾驶舱"],
              ["attack", "攻击演示"],
              ["graph", "证据图谱"],
              ["policy", "策略调试"],
              ["approvals", "审批中心"],
              ["sandbox", "沙箱证据"],
              ["bench", "评测报告"],
            ].map(([id, label]) => <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id as Tab)}>{label}</button>)}
          </nav>
          <div className="tab-page active">
            <div className="title-row">
              <div>
                <h2>{store.selectedRun?.demo_scenario_id || store.selectedRunId || "未选择运行记录"}</h2>
                <p className="muted">来源 {"->"} 指令 {"->"} 动作 {"->"} 决策 {"->"} 响应</p>
              </div>
              <button onClick={exportEvidence}>导出证据包</button>
            </div>
            {tab === "cockpit" && (
              <div className="split">
                <div><RunCockpit run={store.selectedRun} events={store.events} criticalOnly={criticalOnly} activeActionId={store.selectedActionId} setCriticalOnly={setCriticalOnly} onInspectAction={store.inspectAction} /></div>
                <div><h3>决策流</h3><DecisionStream events={store.events} /></div>
              </div>
            )}
            {tab === "attack" && <AttackLab scenarios={store.scenarios} runs={store.runs} onRunScenario={store.runScenario} onOpenRun={store.selectRun} />}
            {tab === "graph" && <TraceGraph nodes={store.graph.nodes} edges={store.graph.edges} activeActionId={store.selectedActionId} onInspectAction={store.inspectAction} />}
            {tab === "policy" && <PolicyDebugger events={store.events} />}
            {tab === "approvals" && <ApprovalCenter events={store.approvals} onGrant={store.grantApproval} onDeny={store.denyApproval} />}
            {tab === "sandbox" && <SandboxEvidence events={store.events} />}
            {tab === "bench" && <BenchReportView bench={store.bench} />}
          </div>
        </section>
        <aside className="detail"><div className="panel-head"><h2>动作详情</h2></div><ActionDetailDrawer detail={store.actionDetail} /></aside>
      </main>
    </>
  );
}
