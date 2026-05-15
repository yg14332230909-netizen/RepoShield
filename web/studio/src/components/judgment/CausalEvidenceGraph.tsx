import { Background, Controls, MarkerType, MiniMap, ReactFlow, type Edge, type Node } from "@xyflow/react";
import type { JudgmentTraceViewModel } from "../../types";
import { displayLabel } from "../DecisionBadge";
import { factName, valueText } from "./format";

const columns = { fact: 0, retrieval: 1, predicate: 2, rule: 3, lattice: 4, final: 5 };

export function CausalEvidenceGraph({ judgment, activeFactId }: { judgment: JudgmentTraceViewModel; activeFactId: string }) {
  const nodes = toNodes(judgment, activeFactId);
  const edges = toEdges(judgment, activeFactId);
  return (
    <section className="judgment-panel causal-graph-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Causal Evidence Graph</span>
        <h3>事实 → 索引召回 → 条件 → 规则 → 决策格 → 最终结论</h3>
      </div>
      <div className="judgment-flow">
        {nodes.length ? (
          <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.25} maxZoom={1.4}>
            <MiniMap zoomable pannable />
            <Controls />
            <Background />
          </ReactFlow>
        ) : <div className="empty-state">暂无因果图节点。</div>}
      </div>
    </section>
  );
}

function toNodes(judgment: JudgmentTraceViewModel, activeFactId: string): Node[] {
  const graph = judgment.causal_graph || {};
  const all = [
    ...(graph.fact_nodes || []).map((node) => ({ ...node, kind: "fact" })),
    ...(graph.retrieval_nodes || []).map((node) => ({ ...node, kind: "retrieval" })),
    ...(graph.predicate_nodes || []).map((node) => ({ ...node, kind: "predicate" })),
    ...(graph.rule_nodes || []).map((node) => ({ ...node, kind: "rule" })),
    ...(graph.lattice_nodes || []).map((node) => ({ ...node, kind: "lattice" })),
    { id: "final_decision", kind: "final", label: judgment.final_decision },
  ];
  const counters = new Map<string, number>();
  return all.filter((node) => node.id).slice(0, 140).map((node) => {
    const kind = String(node.kind);
    const count = counters.get(kind) || 0;
    counters.set(kind, count + 1);
    const label = nodeLabel(node);
    return {
      id: String(node.id),
      position: { x: (columns[kind as keyof typeof columns] || 0) * 240, y: count * 92 },
      data: { label: <div className={`judgment-node ${kind} ${activeFactId && node.id === activeFactId ? "active" : ""}`}><span>{displayLabel(kind)}</span><b>{label}</b></div> },
      style: { width: 210, border: 0, padding: 0, background: "transparent" },
    };
  });
}

function toEdges(judgment: JudgmentTraceViewModel, activeFactId: string): Edge[] {
  return (judgment.causal_graph.edges || []).slice(0, 220).map((edge, index) => {
    const source = String(edge.from || edge.source || "");
    const target = String(edge.to || edge.target || "");
    const relation = String(edge.relation || "related_to");
    const active = activeFactId && (source === activeFactId || target === activeFactId);
    return {
      id: `${source}-${target}-${relation}-${index}`,
      source,
      target,
      label: displayLabel(relation),
      type: "smoothstep",
      animated: relation === "matched" || relation === "candidate" || active,
      markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
      style: { stroke: active ? "#b42318" : relation === "final" ? "#175cd3" : "#98a2b3", strokeWidth: active ? 2.5 : 1.4 },
    };
  }).filter((edge) => edge.source && edge.target);
}

function nodeLabel(node: Record<string, unknown>): string {
  if (node.kind === "fact") return `${factName(node.namespace, node.key)}=${valueText(node.value)}`;
  if (node.kind === "retrieval") return `召回：${String(node.key || node.id)}`;
  if (node.kind === "predicate") return String(node.path || node.key || node.id);
  if (node.kind === "rule") return String(node.rule_id || node.id);
  if (node.kind === "lattice") return `${displayLabel(String(node.from || "start"))} -> ${displayLabel(String(node.to || ""))}`;
  return displayLabel(String(node.label || node.id));
}
