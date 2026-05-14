import type { JudgmentTraceViewModel } from "../../types";
import { DecisionBadge } from "../DecisionBadge";
import { evidenceRefText, oneLineAction, reasonText, severityForDecision } from "./format";

export function JudgmentSummaryBar({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const sourceGroup = judgment.evidence_groups.find((group) => group.group_id === "source");
  const keyFacts = judgment.fact_nodes.slice(0, 3).map((fact) => `${fact.namespace}.${fact.key}=${String(fact.value)}`);
  const invariants = judgment.invariant_hits.map((rule) => String(rule.rule_id || rule.id)).filter(Boolean);
  return (
    <section className="judgment-summary-bar">
      <div>
        <span className="policy-eyebrow">Policy Judgment Workspace</span>
        <h3>{oneLineAction(judgment)}</h3>
        <p>{judgment.why_text || reasonText(judgment)}</p>
      </div>
      <DecisionBadge label={judgment.final_decision} severity={severityForDecision(judgment.final_decision)} />
      <dl>
        <div><dt>Sources</dt><dd>{sourceGroup?.items.map((item) => `${item.label}/${item.value}`).join("、") || "暂无来源证据"}</dd></div>
        <div><dt>Key Facts</dt><dd>{keyFacts.join("、") || "暂无事实节点"}</dd></div>
        <div><dt>Matched Invariants</dt><dd>{invariants.join("、") || "无"}</dd></div>
        <div><dt>Evidence Refs</dt><dd>{evidenceRefText(judgment.evidence_refs)}</dd></div>
      </dl>
    </section>
  );
}
