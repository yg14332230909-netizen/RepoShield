"""Normalize AuditLog/Approval/Bench data into Studio Pro view models."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ActionDetail, RunSummary, StudioEvent
from .redaction import redact_value

PHASES = {
    "gateway_pre_call": "request",
    "source_ingested": "context",
    "task_contract": "contract",
    "gateway_post_call": "model",
    "instruction_ir": "instruction",
    "action_parsed": "action",
    "secret_event": "evidence",
    "package_event": "evidence",
    "mcp_invocation": "evidence",
    "memory_event": "evidence",
    "exec_trace": "sandbox",
    "policy_decision": "policy",
    "policy_runtime": "policy",
    "gateway_approval_request": "approval",
    "gateway_response": "response",
}

DANGEROUS = {
    "install_git_dependency",
    "install_tarball_dependency",
    "install_registry_dependency",
    "read_secret_file",
    "send_network_request",
    "publish_artifact",
    "modify_ci_pipeline",
    "modify_registry_config",
    "invoke_destructive_mcp_tool",
    "unknown_side_effect",
}


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    events: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    # JSONL audit files can be tailed while another process is writing.
                    # Skip incomplete/corrupt lines so Studio stays usable.
                    continue
    return events


def normalize_audit_events(events: list[dict[str, Any]], *, agent_name: str = "local", demo_scenario_id: str | None = None) -> list[StudioEvent]:
    normalized: list[StudioEvent] = []
    trace_by_session: dict[str, str] = {}
    for event in events:
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        session_id = str(event.get("session_id") or "")
        if session_id and payload.get("trace_id") and session_id not in trace_by_session:
            trace_by_session[session_id] = str(payload["trace_id"])
    for idx, event in enumerate(events):
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        trace_id = str(payload.get("trace_id") or trace_by_session.get(str(event.get("session_id") or "")) or event.get("session_id") or "run_default")
        event_type = str(event.get("event_type") or "event")
        run_id = str(payload.get("run_id") or trace_id)
        span_id = _span_id(event_type, payload, event, idx)
        normalized.append(
            StudioEvent(
                schema_version="studio.event.v1",
                event_id=str(event.get("event_id") or f"evt_{idx}"),
                timestamp=str(event.get("timestamp") or event.get("created_at") or ""),
                run_id=run_id,
                session_id=str(event.get("session_id") or ""),
                request_id=str(payload.get("turn_id") or payload.get("request_id") or run_id),
                span_id=span_id,
                parent_span_id=_parent_span(event_type, payload, event),
                event_index=idx,
                type=event_type,
                phase=PHASES.get(event_type, "other"),
                severity=_severity(event_type, payload),
                summary=_summary(event_type, payload),
                agent_name=str(payload.get("agent_name") or agent_name),
                demo_scenario_id=str(payload.get("demo_scenario_id") or demo_scenario_id or "") or None,
                payload=redact_value(_payload_for_ui(event_type, payload, event)),
            )
        )
    return normalized


def build_run_summaries(events: list[StudioEvent]) -> list[RunSummary]:
    runs: dict[str, RunSummary] = {}
    for event in events:
        run = runs.get(event.run_id)
        if not run:
            run = RunSummary(event.run_id, event.session_id, event.timestamp, event.timestamp, agent_name=event.agent_name, demo_scenario_id=event.demo_scenario_id)
            runs[event.run_id] = run
        run.updated_at = event.timestamp or run.updated_at
        run.event_count += 1
        if event.type == "action_parsed":
            run.action_count += 1
        if event.phase == "approval":
            run.approval_count += 1
        if event.severity == "critical":
            run.critical_count += 1
        decision = event.payload.get("decision") or event.payload.get("effective_decision")
        if decision:
            run.latest_decision = str(decision)
        if decision in {"block", "quarantine", "sandbox_then_approval"} or event.payload.get("blocked_count"):
            run.blocked_count += 1
    return sorted(runs.values(), key=lambda r: r.updated_at, reverse=True)


def build_action_detail(events: list[StudioEvent], action_id: str) -> ActionDetail | None:
    related = [e for e in events if e.payload.get("action_id") == action_id or e.span_id == action_id]
    if not related:
        return None
    detail = ActionDetail(action_id=action_id, run_id=related[0].run_id)
    source_ids: set[str] = set()
    for event in related:
        if event.type == "action_parsed":
            detail.action = dict(event.payload)
            source_ids.update(str(s) for s in event.payload.get("source_ids", []) or [])
        elif event.type == "policy_decision":
            detail.decision = dict(event.payload)
        elif event.type == "policy_runtime":
            detail.runtime = dict(event.payload)
        elif event.type == "instruction_ir":
            detail.instruction = dict(event.payload)
        detail.evidence_events.append(event.to_dict())
    for event in events:
        if event.type == "source_ingested" and event.payload.get("source_id") in source_ids:
            detail.sources.append(event.payload)
    return detail


def graph_for_run(events: list[StudioEvent], run_id: str) -> dict[str, Any]:
    run_events = [e for e in events if e.run_id == run_id]
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    for e in run_events:
        node_id = e.span_id
        nodes[node_id] = {"id": node_id, "type": e.type, "phase": e.phase, "severity": e.severity, "label": e.summary}
        for sid in e.payload.get("source_ids", []) or []:
            nodes.setdefault(str(sid), {"id": str(sid), "type": "source", "phase": "context", "severity": "info", "label": str(sid)})
            edges.append({"from": str(sid), "to": node_id, "relation": "influenced"})
        for ref in e.payload.get("evidence_refs", []) or []:
            nodes.setdefault(str(ref), {"id": str(ref), "type": "evidence", "phase": "evidence", "severity": "info", "label": str(ref)})
            edges.append({"from": str(ref), "to": node_id, "relation": "evidence"})
        if e.parent_span_id:
            edges.append({"from": e.parent_span_id, "to": node_id, "relation": "parent"})
    return {"nodes": list(nodes.values()), "edges": edges}


def _span_id(event_type: str, payload: dict[str, Any], event: dict[str, Any], index: int) -> str:
    if event_type == "policy_decision":
        return str(event.get("decision_id") or payload.get("decision_id") or event.get("event_id") or f"decision_{index}")
    if event_type == "policy_runtime":
        return str(event.get("decision_id") or payload.get("decision_id") or event.get("event_id") or f"runtime_{index}")
    if event_type == "exec_trace":
        return str(payload.get("exec_trace_id") or event.get("event_id") or f"exec_{index}")
    if event_type == "package_event":
        return str(payload.get("package_event_id") or event.get("event_id") or f"package_{index}")
    if event_type == "secret_event":
        return str(payload.get("secret_event_id") or event.get("event_id") or f"secret_{index}")
    if event_type == "gateway_approval_request":
        return str(payload.get("approval_request_id") or event.get("event_id") or f"approval_{index}")
    return str(event.get("action_id") or payload.get("action_id") or event.get("decision_id") or payload.get("decision_id") or event.get("event_id") or f"event_{index}")


def _payload_for_ui(event_type: str, payload: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    for key in ("action_id", "decision_id", "source_ids"):
        if event.get(key) and key not in out:
            out[key] = event[key]
    return out


def _parent_span(event_type: str, payload: dict[str, Any], event: dict[str, Any]) -> str | None:
    if event_type in {"policy_decision", "policy_runtime", "exec_trace", "secret_event", "package_event"}:
        return str(event.get("action_id") or payload.get("action_id") or "") or None
    if event_type == "action_parsed":
        return str(payload.get("instruction_id") or payload.get("lowered_from_instruction_id") or "") or None
    return None


def _severity(event_type: str, payload: dict[str, Any]) -> str:
    decision = str(payload.get("decision") or payload.get("effective_decision") or "")
    semantic = str(payload.get("semantic_action") or "")
    risk = str(payload.get("risk") or "")
    if decision in {"block", "quarantine"} or risk == "critical" or semantic in DANGEROUS:
        return "critical"
    if decision in {"sandbox_then_approval", "allow_in_sandbox"} or risk == "high":
        return "warning"
    if event_type in {"gateway_response", "gateway_pre_call", "gateway_post_call"}:
        return "info"
    return "normal"


def _summary(event_type: str, payload: dict[str, Any]) -> str:
    if event_type == "policy_decision":
        return f"{payload.get('decision', 'decision')} {payload.get('semantic_action', payload.get('action_id', 'action'))}"
    if event_type == "policy_runtime":
        return f"runtime {payload.get('effective_decision', '')}"
    if event_type == "action_parsed":
        return f"{payload.get('semantic_action', 'action')}: {payload.get('raw_action', '')}"[:180]
    if event_type == "source_ingested":
        return f"source {payload.get('source_id', '')} ({payload.get('source_type', '')})"
    if event_type == "instruction_ir":
        return f"instruction {payload.get('kind', payload.get('instruction_type', ''))}"
    if event_type == "gateway_response":
        return f"gateway response blocked={payload.get('blocked_count', 0)}"
    return event_type.replace("_", " ")
