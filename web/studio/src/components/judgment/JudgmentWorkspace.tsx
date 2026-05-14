import { useState } from "react";
import type { JudgmentTraceViewModel } from "../../types";
import { CausalEvidenceGraph } from "./CausalEvidenceGraph";
import { CounterfactualPanel } from "./CounterfactualPanel";
import { DecisionLatticeStepper } from "./DecisionLatticeStepper";
import { EvidenceIntakePanel } from "./EvidenceIntakePanel";
import { FactMatrix } from "./FactMatrix";
import { InvariantGateView } from "./InvariantGateView";
import { JudgmentSummaryBar } from "./JudgmentSummaryBar";
import { PredicateMatrix } from "./PredicateMatrix";
import { RuleCandidatePruner } from "./RuleCandidatePruner";
import { WhyDecisionPanel } from "./WhyDecisionPanel";

export function JudgmentWorkspace({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const [activeFactId, setActiveFactId] = useState("");
  const [activeRefs, setActiveRefs] = useState<string[]>([]);
  return (
    <div className="judgment-workspace">
      <JudgmentSummaryBar judgment={judgment} />
      <div className="judgment-layout">
        <div className="judgment-column left">
          <EvidenceIntakePanel judgment={judgment} activeFactRefs={activeRefs} />
          <FactMatrix judgment={judgment} activeFactId={activeFactId} onSelectFact={(factId, refs) => { setActiveFactId(factId); setActiveRefs(refs); }} />
        </div>
        <div className="judgment-column right">
          <InvariantGateView judgment={judgment} />
          <RuleCandidatePruner judgment={judgment} />
          <PredicateMatrix judgment={judgment} />
          <DecisionLatticeStepper judgment={judgment} />
          <WhyDecisionPanel judgment={judgment} />
          <CounterfactualPanel judgment={judgment} />
        </div>
      </div>
      <CausalEvidenceGraph judgment={judgment} activeFactId={activeFactId} />
    </div>
  );
}
