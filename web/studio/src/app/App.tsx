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
import { PolicyJudgment } from "../routes/PolicyJudgment";
import { useRunStore } from "../state/useRunStore";
import { runSubtitle, runTitle, shortId } from "../components/displayText";

type Tab = "cockpit" | "attack" | "graph" | "judgment" | "policy" | "approvals" | "sandbox" | "bench";

const tabs: Array<[Tab, string]> = [
  ["cockpit", "本次运行"],
  ["attack", "攻击演示"],
  ["graph", "安全决策追踪图"],
  ["judgment", "综合判断"],
  ["policy", "拦截原因"],
  ["approvals", "人工审批"],
  ["sandbox", "沙箱预检"],
  ["bench", "安全成绩单"],
];

const guideSteps = [
  "选择或运行一个场景",
  "看时间线发生了什么",
  "看图谱追踪证据",
  "看拦截原因和审批",
  "用成绩单验证整体效果",
];

export function App() {
  const store = useRunStore();
  const [criticalOnly, setCriticalOnly] = useState(false);
  const [tab, setTab] = useState<Tab>("cockpit");
  const mode = store.health ? (store.health.demo_mode ? "演示模式" : "实时模式") : "连接中";
  const liveLabel = store.liveStatus === "error" ? "同步异常" : store.liveStatus === "syncing" ? "同步中" : "自动观测中";
  const lastRefresh = store.lastUpdatedAt ? new Date(store.lastUpdatedAt).toLocaleTimeString() : "等待同步";

  async function refreshAll() {
    await store.refreshRuns();
    await store.refreshSecondary();
  }

  async function exportEvidence() {
    const output = await store.exportEvidence();
    if (output) window.alert(`证据包已导出到 ${output}`);
  }

  async function clearRecords() {
    const ok = window.confirm("确定清空当前 Studio 的演示记录和审批记录吗？\n\n这只会清空本地日志文件，不会删除项目代码。");
    if (!ok) return;
    const backup = window.confirm("是否在清空前备份当前记录？\n\n选择“确定”会保存备份；选择“取消”会直接清空，不保留备份。");
    const result = await store.clearRecords(backup);
    if (result.backup_enabled && result.backups.length) {
      window.alert(`演示记录已清空，备份已保存到：\n${result.backups.join("\n")}`);
    } else if (result.backup_enabled) {
      window.alert("演示记录已清空。本次没有可备份内容。");
    } else {
      window.alert("演示记录已清空，未创建备份。");
    }
  }

  return (
    <>
      <header className="topbar">
        <div><h1>RepoShield Studio Pro</h1><p>看见 coding agent 为什么被放行、沙箱执行、要求审批或阻断。</p></div>
        <div className="topbar-actions">
          <span className="status-pill">{store.health?.version || "等待服务"} · {mode}</span>
          <span className={`status-pill live ${store.liveStatus}`}><i />{liveLabel} · {lastRefresh}</span>
          <TokenControl />
          <button onClick={refreshAll}>刷新</button>
        </div>
      </header>
      <main className="shell">
        <aside className="sidebar">
          <div className="panel-head"><h2>运行记录</h2><span className="muted">{store.runs.length}</span></div>
          <div className="side-note">每张卡片是一轮代理请求：正常任务会被沙箱约束，攻击载荷会被解释并阻断。</div>
          <div className="run-tools">
            <button onClick={clearRecords} disabled={!store.runs.length && !store.approvals.length}>清空演示记录</button>
          </div>
          <div className="run-list">
            {store.runs.length ? store.runs.map((run) => (
              <button key={run.run_id} className={`run-card ${run.run_id === store.selectedRunId ? "active" : ""}`} onClick={() => store.selectRun(run.run_id)}>
                <b>{runTitle(run)}</b>
                <span className="run-id">#{shortId(run.run_id)}</span>
                <div className="run-purpose">{runSubtitle(run)}</div>
                <div className="muted">{run.event_count} 个事件 · {run.action_count} 个动作</div>
                <DecisionBadge label={run.latest_decision || "observing"} severity={run.blocked_count ? "critical" : "normal"} />
              </button>
            )) : <div className="sidebar-empty">暂无运行记录。先去“攻击演示”运行一个样本。</div>}
          </div>
        </aside>
        <section className="workspace">
          <nav className="tabs" aria-label="Studio 分区">
            {tabs.map(([id, label]) => <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>{label}</button>)}
          </nav>
          <div className="tab-page active">
            <div className="guided-tour">
              {guideSteps.map((step, index) => <span key={step} className={index === 0 && !store.runs.length ? "active" : ""}>{index + 1}. {step}</span>)}
            </div>
            <div className="title-row">
              <div>
                <h2>{store.selectedRun ? runTitle(store.selectedRun) : "未选择运行记录"}</h2>
                <p className="muted">{store.selectedRun ? runSubtitle(store.selectedRun) : "选择左侧运行记录，查看 RepoShield 如何追踪来源、识别动作并做出安全决策。"}</p>
              </div>
              <button onClick={exportEvidence}>导出证据包</button>
            </div>
            {!store.runs.length && tab !== "attack" ? (
              <div className="empty-guide">
                <h3>当前还没有代理请求</h3>
                <p>这是一个干净的初始状态。你可以先进入“攻击演示”运行一个样本，或把真实网关审计日志接入当前服务。</p>
                <button className="primary" onClick={() => setTab("attack")}>去运行攻击演示</button>
              </div>
            ) : null}
            {store.runs.length > 0 && tab === "cockpit" && (
              <div className="split">
                <div><RunCockpit run={store.selectedRun} events={store.events} criticalOnly={criticalOnly} activeActionId={store.selectedActionId} setCriticalOnly={setCriticalOnly} onInspectAction={store.inspectAction} /></div>
                <div><h3>决策流</h3><DecisionStream events={store.events} /></div>
              </div>
            )}
            {tab === "attack" && <AttackLab scenarios={store.scenarios} runs={store.runs} onRunScenario={store.runScenario} onOpenRun={store.selectRun} />}
            {tab === "graph" && <TraceGraph nodes={store.graph.nodes} edges={store.graph.edges} activeActionId={store.selectedActionId} onInspectAction={store.inspectAction} />}
            {tab === "judgment" && <PolicyJudgment judgment={store.actionJudgment} events={store.events} onInspectAction={store.inspectAction} />}
            {tab === "policy" && <PolicyDebugger events={store.events} />}
            {tab === "approvals" && <ApprovalCenter events={store.approvals} onGrant={store.grantApproval} onDeny={store.denyApproval} />}
            {tab === "sandbox" && <SandboxEvidence events={store.events} />}
            {tab === "bench" && <BenchReportView bench={store.bench} />}
          </div>
        </section>
        <aside className="detail"><div className="panel-head"><h2>动作详情</h2></div><ActionDetailDrawer detail={store.actionDetail} onOpenJudgment={() => setTab("judgment")} /></aside>
      </main>
    </>
  );
}
