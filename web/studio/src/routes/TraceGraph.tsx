import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from "@xyflow/react";
import type { GraphEdge, GraphNode } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";

const phaseOrder = ["context", "instruction", "action", "sandbox", "policy", "approval", "response", "evidence", "other"];

function nodePosition(node: GraphNode, index: number, phaseCounts: Map<string, number>): { x: number; y: number } {
  const phase = phaseOrder.includes(node.phase) ? node.phase : "other";
  const phaseIndex = phaseOrder.indexOf(phase);
  const count = phaseCounts.get(phase) || 0;
  phaseCounts.set(phase, count + 1);
  return { x: phaseIndex * 245, y: count * 112 + (index % 2) * 10 };
}

function toFlowNodes(nodes: GraphNode[], onInspectAction: (actionId: string) => void): Node[] {
  const phaseCounts = new Map<string, number>();
  return nodes.map((node, index) => ({
    id: node.id,
    position: nodePosition(node, index, phaseCounts),
    data: {
      label: (
        <button className={`flow-node ${node.severity}`} onClick={() => node.phase === "action" && onInspectAction(node.id)}>
          <span>{node.phase} · {node.type}</span>
          <b>{node.label}</b>
        </button>
      )
    },
    style: { width: 210, border: "0", padding: 0, background: "transparent" },
    draggable: true,
  }));
}

function toFlowEdges(edges: GraphEdge[]): Edge[] {
  return edges.slice(0, 220).map((edge, index) => ({
    id: `${edge.from}-${edge.to}-${edge.relation}-${index}`,
    source: edge.from,
    target: edge.to,
    label: edge.relation,
    animated: edge.relation === "influenced",
    style: { stroke: edge.relation === "evidence" ? "#175cd3" : "#98a2b3", strokeWidth: edge.relation === "influenced" ? 2 : 1.4 },
  }));
}

export function TraceGraph({ nodes, edges, onInspectAction }: { nodes: GraphNode[]; edges: GraphEdge[]; onInspectAction: (actionId: string) => void }) {
  const flowNodes = toFlowNodes(nodes, onInspectAction);
  const flowEdges = toFlowEdges(edges);
  const byPhase = phaseOrder.map((phase) => [phase, nodes.filter((node) => node.phase === phase).length] as const).filter(([, count]) => count);
  return (
    <>
      <div className="graph-toolbar">
        {byPhase.map(([phase, count]) => <DecisionBadge key={phase} label={`${phase}: ${count}`} severity={phase === "action" || phase === "policy" ? "warning" : "info"} />)}
      </div>
      <div className="trace-graph">
        {flowNodes.length ? (
          <ReactFlow nodes={flowNodes} edges={flowEdges} fitView minZoom={0.25} maxZoom={1.4}>
            <MiniMap zoomable pannable />
            <Controls />
            <Background />
          </ReactFlow>
        ) : <div className="empty-state">No graph nodes yet.</div>}
      </div>
      <pre className="json-block">{JSON.stringify(edges.slice(0, 80), null, 2)}</pre>
    </>
  );
}
