export type Severity = "critical" | "warning" | "normal" | "info";

export interface StudioEvent {
  schema_version: string;
  event_id: string;
  timestamp: string;
  run_id: string;
  session_id: string;
  request_id: string;
  span_id: string;
  parent_span_id?: string | null;
  event_index: number;
  type: string;
  phase: string;
  severity: Severity;
  summary: string;
  agent_name: string;
  demo_scenario_id?: string | null;
  payload: Record<string, unknown>;
}

export interface RunSummary {
  run_id: string;
  session_id: string;
  started_at: string;
  updated_at: string;
  event_count: number;
  blocked_count: number;
  approval_count: number;
  action_count: number;
  critical_count: number;
  latest_decision: string;
  agent_name: string;
  demo_scenario_id?: string | null;
}

export interface ActionDetail {
  action_id: string;
  run_id: string;
  action: Record<string, unknown>;
  decision: Record<string, unknown>;
  runtime: Record<string, unknown>;
  instruction: Record<string, unknown>;
  sources: Array<Record<string, unknown>>;
  evidence_events: StudioEvent[];
}

export interface ScenarioSpec {
  id: string;
  name: string;
  kind: "normal" | "attack";
  description: string;
  source_type: string;
  attack_body: string;
  expected_decision: string;
  dangerous_action: string;
}

export interface GraphNode {
  id: string;
  type: string;
  phase: string;
  severity: Severity;
  label: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  relation: string;
}

export interface ApprovalEvent {
  event_type: "request" | "grant" | "denial" | string;
  created_at?: string;
  payload: Record<string, unknown>;
}

export interface BenchReport {
  metrics: Record<string, unknown>;
  samples: Array<Record<string, unknown>>;
}
