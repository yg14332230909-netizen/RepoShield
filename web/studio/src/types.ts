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
  policy_fact_set?: Record<string, unknown>;
  policy_eval_trace?: PolicyEvalTrace;
  policy_predicates?: PolicyPredicateRow[];
  policy_lattice_path?: Array<Record<string, unknown>>;
  policy_causal_graph?: PolicyCausalGraph;
}

export interface PolicyPredicateRow {
  rule_id?: string;
  rule_decision?: string;
  rule_invariant?: boolean;
  predicate_id?: string;
  path?: string;
  operator?: string;
  expected?: unknown;
  actual?: unknown;
  matched?: boolean;
  matched_fact_ids?: string[];
  evidence_refs?: string[];
}

export interface PolicyCausalGraph {
  fact_nodes?: Array<Record<string, unknown>>;
  predicate_nodes?: Array<Record<string, unknown>>;
  rule_nodes?: Array<Record<string, unknown>>;
  lattice_nodes?: Array<Record<string, unknown>>;
  retrieval_nodes?: Array<Record<string, unknown>>;
  edges?: Array<Record<string, unknown>>;
}

export interface PolicyEvalTrace extends PolicyCausalGraph {
  action_id?: string;
  policy_eval_trace_id?: string;
  final_decision?: string;
  engine_mode?: string;
  policy_version?: string;
  fact_hash?: string;
  invariant_hits?: string[];
  decision_lattice_path?: Array<Record<string, unknown>>;
  skipped_rules_summary?: Record<string, unknown>;
}

export type JudgmentSourceModule =
  | "ActionIR"
  | "ContextGraph"
  | "AssetGraph"
  | "SecretSentry"
  | "PackageGuard"
  | "MCPProxy"
  | "MemoryStore"
  | "SandboxRunner"
  | "TaskContract"
  | "PolicyGraph";

export interface JudgmentEvidenceItem {
  id: string;
  label: string;
  value: unknown;
  evidence_refs: string[];
  source_module: JudgmentSourceModule;
}

export interface JudgmentEvidenceGroup {
  group_id: string;
  label: string;
  severity: Severity;
  items: JudgmentEvidenceItem[];
}

export interface JudgmentTraceViewModel {
  schema_version: string;
  action_id: string;
  run_id: string;
  action_summary: Record<string, unknown>;
  evidence_groups: JudgmentEvidenceGroup[];
  fact_set: Record<string, unknown>;
  fact_nodes: Array<Record<string, unknown>>;
  invariant_hits: Array<Record<string, unknown>>;
  candidate_rules: Array<Record<string, unknown>>;
  predicate_rows: PolicyPredicateRow[];
  lattice_path: Array<Record<string, unknown>>;
  causal_graph: PolicyCausalGraph;
  final_decision: string;
  reason_codes: string[];
  required_controls: string[];
  evidence_refs: string[];
  why_text: string;
  skipped_rules_summary?: Record<string, unknown>;
  retrieval_trace?: Record<string, unknown>;
  policy_eval_trace_id?: string;
  fact_hash?: string;
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
