import { useState } from "react";
import { ActionDetailDrawer } from "../components/ActionDetailDrawer";
import { DecisionBadge } from "../components/DecisionBadge";
import { DecisionStream } from "../components/DecisionStream";
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

  async function refreshAll() {
    await store.refreshRuns();
    await store.refreshSecondary();
  }

  async function exportEvidence() {
    const output = await store.exportEvidence();
    if (output) window.alert(`Evidence exported to ${output}`);
  }

  return (
    <>
      <header className="topbar">
        <div><h1>RepoShield Studio Pro</h1><p>React/Vite frontend for live coding-agent governance observability.</p></div>
        <div className="topbar-actions">
          <span className="status-pill">{store.health?.version || "connecting"} {store.health?.demo_mode ? "demo" : "live"}</span>
          <button onClick={refreshAll}>Refresh</button>
        </div>
      </header>
      <main className="shell">
        <aside className="sidebar">
          <div className="panel-head"><h2>Runs</h2><span className="muted">{store.runs.length}</span></div>
          <div className="run-list">
            {store.runs.map((run) => (
              <button key={run.run_id} className={`run-card ${run.run_id === store.selectedRunId ? "active" : ""}`} onClick={() => store.selectRun(run.run_id)}>
                <b>{run.demo_scenario_id || run.run_id}</b>
                <div className="muted">{run.event_count} events · {run.action_count} actions</div>
                <DecisionBadge label={run.latest_decision || "observing"} severity={run.blocked_count ? "critical" : "normal"} />
              </button>
            ))}
          </div>
        </aside>
        <section className="workspace">
          <nav className="tabs" aria-label="Studio sections">
            {[
              ["cockpit", "Run Cockpit"],
              ["attack", "Attack Lab"],
              ["graph", "Trace Graph"],
              ["policy", "Policy Debugger"],
              ["approvals", "Approval Center"],
              ["sandbox", "Sandbox Evidence"],
              ["bench", "Bench & Report"],
            ].map(([id, label]) => <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id as Tab)}>{label}</button>)}
          </nav>
          <div className="tab-page active">
            <div className="title-row">
              <div>
                <h2>{store.selectedRun?.demo_scenario_id || store.selectedRunId || "No run selected"}</h2>
                <p className="muted">source {"->"} instruction {"->"} action {"->"} decision {"->"} response</p>
              </div>
              <button onClick={exportEvidence}>Export Evidence</button>
            </div>
            {tab === "cockpit" && (
              <div className="split">
                <div><RunCockpit run={store.selectedRun} events={store.events} criticalOnly={criticalOnly} setCriticalOnly={setCriticalOnly} onInspectAction={store.inspectAction} /></div>
                <div><h3>Decision Stream</h3><DecisionStream events={store.events} /></div>
              </div>
            )}
            {tab === "attack" && <AttackLab scenarios={store.scenarios} runs={store.runs} onRunScenario={store.runScenario} onOpenRun={store.selectRun} />}
            {tab === "graph" && <TraceGraph nodes={store.graph.nodes} edges={store.graph.edges} onInspectAction={store.inspectAction} />}
            {tab === "policy" && <PolicyDebugger events={store.events} />}
            {tab === "approvals" && <ApprovalCenter events={store.approvals} onGrant={store.grantApproval} onDeny={store.denyApproval} />}
            {tab === "sandbox" && <SandboxEvidence events={store.events} />}
            {tab === "bench" && <BenchReportView bench={store.bench} />}
          </div>
        </section>
        <aside className="detail"><div className="panel-head"><h2>Action Detail</h2></div><ActionDetailDrawer detail={store.actionDetail} /></aside>
      </main>
    </>
  );
}
