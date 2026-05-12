import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { studioApi } from "../api/client";
import { subscribeToRun } from "../api/events";
import type { ActionDetail, ApprovalEvent, BenchReport, GraphEdge, GraphNode, RunSummary, ScenarioSpec, StudioEvent } from "../types";

export function useRunStore() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string>("");
  const [events, setEvents] = useState<StudioEvent[]>([]);
  const [graph, setGraph] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] }>({ nodes: [], edges: [] });
  const [actionDetail, setActionDetail] = useState<ActionDetail | null>(null);
  const [scenarios, setScenarios] = useState<ScenarioSpec[]>([]);
  const [approvals, setApprovals] = useState<ApprovalEvent[]>([]);
  const [bench, setBench] = useState<BenchReport>({ metrics: {}, samples: [] });
  const [health, setHealth] = useState<{ version: string; demo_mode: boolean } | null>(null);
  const sourceRef = useRef<EventSource | null>(null);

  const refreshRuns = useCallback(async () => {
    const next = (await studioApi.runs()).runs;
    setRuns(next);
    if (!selectedRunId && next[0]) setSelectedRunId(next[0].run_id);
  }, [selectedRunId]);

  const refreshSecondary = useCallback(async () => {
    const [healthResult, scenarioResult, approvalResult, benchResult] = await Promise.all([
      studioApi.health(),
      studioApi.scenarios(),
      studioApi.approvals(),
      studioApi.bench(),
    ]);
    setHealth({ version: healthResult.version, demo_mode: healthResult.demo_mode });
    setScenarios(scenarioResult.scenarios);
    setApprovals(approvalResult.events);
    setBench(benchResult);
  }, []);

  const selectRun = useCallback(async (runId: string) => {
    setSelectedRunId(runId);
    const [eventResult, graphResult] = await Promise.all([studioApi.events(runId), studioApi.graph(runId)]);
    setEvents(eventResult.events);
    setGraph(graphResult);
    sourceRef.current?.close();
    sourceRef.current = subscribeToRun(runId, (event) => {
      setEvents((existing) => existing.some((item) => item.event_id === event.event_id) ? existing : [...existing, event]);
    });
  }, []);

  const inspectAction = useCallback(async (actionId: string) => {
    setActionDetail(await studioApi.action(actionId));
  }, []);

  const runScenario = useCallback(async (scenarioId: string) => {
    const result = await studioApi.runScenario(scenarioId);
    await refreshRuns();
    await refreshSecondary();
    await selectRun(result.result.trace_id);
  }, [refreshRuns, refreshSecondary, selectRun]);

  const grantApproval = useCallback(async (approvalId: string, actionHash: string) => {
    await studioApi.grant(approvalId, actionHash);
    const approvalResult = await studioApi.approvals();
    setApprovals(approvalResult.events);
  }, []);

  const denyApproval = useCallback(async (approvalId: string) => {
    await studioApi.deny(approvalId);
    const approvalResult = await studioApi.approvals();
    setApprovals(approvalResult.events);
  }, []);

  const exportEvidence = useCallback(async () => {
    if (!selectedRunId) return "";
    const result = await studioApi.exportEvidence(selectedRunId);
    return result.output;
  }, [selectedRunId]);

  useEffect(() => {
    refreshRuns();
    refreshSecondary();
    return () => sourceRef.current?.close();
  }, [refreshRuns, refreshSecondary]);

  useEffect(() => {
    if (selectedRunId) selectRun(selectedRunId);
  }, [selectedRunId, selectRun]);

  const selectedRun = useMemo(() => runs.find((run) => run.run_id === selectedRunId) || null, [runs, selectedRunId]);

  return {
    runs,
    selectedRun,
    selectedRunId,
    events,
    graph,
    actionDetail,
    scenarios,
    approvals,
    bench,
    health,
    refreshRuns,
    refreshSecondary,
    selectRun,
    inspectAction,
    runScenario,
    grantApproval,
    denyApproval,
    exportEvidence,
  };
}
