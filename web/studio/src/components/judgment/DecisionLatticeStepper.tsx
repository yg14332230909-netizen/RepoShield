import type { JudgmentTraceViewModel } from "../../types";
import { displayLabel } from "../DecisionBadge";
import { ruleTitle } from "./format";

const decisionOrder = ["allow", "allow_in_sandbox", "sandbox_then_approval", "quarantine", "block"];

export function DecisionLatticeStepper({ judgment }: { judgment: JudgmentTraceViewModel }) {
  return (
    <section className="judgment-panel lattice-stepper-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Decision Lattice</span>
        <h3>多规则结果如何合并为最终裁决</h3>
      </div>
      <div className="lattice-rail">
        {decisionOrder.map((decision) => <span className={rank(decision) <= rank(judgment.final_decision) ? "active" : ""} key={decision}>{displayLabel(decision)}</span>)}
      </div>
      <div className="lattice-step-list">
        {judgment.lattice_path.map((step, index) => (
          <div className="lattice-step-card" key={`${step.via}-${index}`}>
            <span>{displayLabel(String(step.from || "开始"))} → {displayLabel(String(step.to || "决策"))}</span>
            <b>{ruleTitle({ rule_id: step.via })}</b>
          </div>
        ))}
      </div>
      {!judgment.lattice_path.length ? <div className="empty-state">该动作没有决策格路径。最终结论仍显示在页面顶部。</div> : null}
    </section>
  );
}

function rank(decision: string): number {
  const idx = decisionOrder.indexOf(decision);
  return idx >= 0 ? idx : 0;
}
