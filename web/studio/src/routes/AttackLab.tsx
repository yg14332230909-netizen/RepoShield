import type { RunSummary, ScenarioSpec } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";

function runCard(run?: RunSummary) {
  if (!run) return <div className="empty-state">Run this side of the story first.</div>;
  return (
    <div className="compare-column">
      <b>{run.demo_scenario_id || run.run_id}</b>
      <div className="muted">{run.event_count} events · {run.action_count} actions · {run.agent_name}</div>
      <DecisionBadge label={run.latest_decision || "observing"} severity={run.blocked_count ? "critical" : "normal"} />
    </div>
  );
}

export function AttackLab({ scenarios, runs, onRunScenario, onOpenRun }: { scenarios: ScenarioSpec[]; runs: RunSummary[]; onRunScenario: (scenarioId: string) => void; onOpenRun: (runId: string) => void }) {
  const normal = runs.find((run) => run.demo_scenario_id === "normal-login-fix");
  const attack = runs.find((run) => run.demo_scenario_id && run.demo_scenario_id !== "normal-login-fix");
  return (
    <>
      <div className="scenario-grid">
        {scenarios.map((scenario) => (
          <div className="scenario-card" key={scenario.id}>
            <DecisionBadge label={scenario.kind} severity={scenario.kind === "attack" ? "critical" : "normal"} />
            <h3>{scenario.name}</h3>
            <p className="muted">{scenario.description}</p>
            <div className="muted">Expected: {scenario.dangerous_action} {"->"} {scenario.expected_decision}</div>
            <button className="primary" onClick={() => onRunScenario(scenario.id)}>Run scenario</button>
          </div>
        ))}
      </div>
      <h3>Normal / Attack Comparator</h3>
      <div className="comparator">
        <button onClick={() => normal && onOpenRun(normal.run_id)}>{runCard(normal)}</button>
        <button onClick={() => attack && onOpenRun(attack.run_id)}>{runCard(attack)}</button>
      </div>
    </>
  );
}
