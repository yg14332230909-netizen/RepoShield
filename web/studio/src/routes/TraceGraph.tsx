import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from "@xyflow/react";
import type { GraphEdge, GraphNode } from "../types";
import { DecisionBadge, displayLabel } from "../components/DecisionBadge";
import { graphEdgeLabel, graphNodeDetail, graphNodeTitle } from "../components/displayText";

const phaseOrder = ["context", "instruction", "action", "sandbox", "policy", "approval", "response", "evidence", "other"];

function nodePosition(node: GraphNode, index: number, phaseCounts: Map<string, number>): { x: number; y: number } {
  const phase = phaseOrder.includes(node.phase) ? node.phase : "other";
  const phaseIndex = phaseOrder.indexOf(phase);
  const count = phaseCounts.get(phase) || 0;
  phaseCounts.set(phase, count + 1);
  return { x: phaseIndex * 245, y: count * 112 + (index % 2) * 10 };
}

function connectedTo(activeNodeId: string, edges: GraphEdge[]): Set<string> {
  if (!activeNodeId) return new Set();
  const connected = new Set([activeNodeId]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const edge of edges) {
      if (connected.has(edge.from) && !connected.has(edge.to)) {
        connected.add(edge.to);
        changed = true;
      }
      if (connected.has(edge.to) && !connected.has(edge.from)) {
        connected.add(edge.from);
        changed = true;
      }
    }
  }
  return connected;
}

function toFlowNodes(nodes: GraphNode[], edges: GraphEdge[], activeActionId: string, onInspectAction: (actionId: string) => void): Node[] {
  const phaseCounts = new Map<string, number>();
  const activePath = connectedTo(activeActionId, edges);
  return nodes.map((node, index) => ({
    id: node.id,
    position: nodePosition(node, index, phaseCounts),
    data: {
      label: (
        <button className={`flow-node ${node.severity} ${node.id === activeActionId ? "selected" : ""} ${activePath.has(node.id) ? "connected" : activeActionId ? "dimmed" : ""}`} onClick={() => node.phase === "action" && onInspectAction(node.id)}>
          <span>{displayLabel(node.phase)}</span>
          <b>{graphNodeTitle(node)}</b>
          <small>{graphNodeDetail(node)}</small>
        </button>
      )
    },
    style: { width: 240, border: "0", padding: 0, background: "transparent" },
    draggable: true,
  }));
}

function toFlowEdges(edges: GraphEdge[], activeActionId: string): Edge[] {
  const activePath = connectedTo(activeActionId, edges);
  return edges.slice(0, 220).map((edge, index) => ({
    id: `${edge.from}-${edge.to}-${edge.relation}-${index}`,
    source: edge.from,
    target: edge.to,
    label: graphEdgeLabel(edge.relation),
    animated: edge.relation === "influenced",
    style: {
      stroke: activePath.has(edge.from) && activePath.has(edge.to) ? "#b42318" : edge.relation === "evidence" ? "#175cd3" : "#98a2b3",
      strokeWidth: activePath.has(edge.from) && activePath.has(edge.to) ? 2.6 : edge.relation === "influenced" ? 2 : 1.4,
      opacity: activeActionId && !(activePath.has(edge.from) && activePath.has(edge.to)) ? 0.28 : 1,
    },
  }));
}

export function TraceGraph({ nodes, edges, activeActionId, onInspectAction }: { nodes: GraphNode[]; edges: GraphEdge[]; activeActionId: string; onInspectAction: (actionId: string) => void }) {
  const flowNodes = toFlowNodes(nodes, edges, activeActionId, onInspectAction);
  const flowEdges = toFlowEdges(edges, activeActionId);
  const byPhase = phaseOrder.map((phase) => [phase, nodes.filter((node) => node.phase === phase).length] as const).filter(([, count]) => count);
  return (
    <>
      <div className="graph-explainer">
        <b>安全决策追踪图</b>
        <span>从“信息来源”一路追到“工具动作”和“策略结论”，用来说明 RepoShield 为什么放行、沙箱、审批或阻断。</span>
      </div>
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
        ) : <div className="empty-state">暂无图谱节点。</div>}
      </div>
      <details className="raw-graph">
        <summary>查看原始审计关系</summary>
        <pre className="json-block">{JSON.stringify(edges.slice(0, 80), null, 2)}</pre>
      </details>
    </>
  );
}
