"""RepoShield OpenAI-compatible Governance Gateway."""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..approvals import ApprovalCenter, ApprovalStore
from ..audit import AuditLog
from ..control_plane import RepoShieldControlPlane
from ..instruction_ir import InstructionBuilder, InstructionLowerer
from ..instruction_ir import to_dict as instruction_to_dict
from ..models import new_id, sha256_json
from ..plugins import ToolParserRegistry
from ..policy_runtime import PolicyRuntime
from .openai_compat import chat_completion_stream_events, extract_messages, latest_user_text, responses_api_response
from .response_transform import transform_response
from .trace_state import GatewayTrace
from .upstream import LocalHeuristicUpstream, OpenAICompatibleUpstream


class RepoShieldGateway:
    def __init__(
        self,
        repo_root: str | Path,
        audit_path: str | Path | None = None,
        policy_mode: str = "enforce",
        policy_role: str = "local_dev_strict",
        upstream: Any | None = None,
        agent_type: str = "openai",
        policy_config: str | Path | None = None,
        release_mode: str = "gateway_only",
        approval_store_path: str | Path | None = None,
        unsafe_allow_disabled_policy: bool = False,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.audit = AuditLog(audit_path or self.repo_root / ".reposhield" / "gateway_audit.jsonl")
        self.policy_config = policy_config
        self.cp = self._new_request_control_plane()
        self.policy_runtime = PolicyRuntime(mode=policy_mode, role=policy_role, unsafe_allow_disabled=unsafe_allow_disabled_policy)  # type: ignore[arg-type]
        self.upstream = upstream or LocalHeuristicUpstream()
        self.agent_type = agent_type
        self.registry = ToolParserRegistry()
        self.release_mode = release_mode
        self.approvals = ApprovalCenter()
        self.approval_store = ApprovalStore(approval_store_path or self.repo_root / ".reposhield" / "gateway_approvals.jsonl")

    def _new_request_control_plane(self) -> RepoShieldControlPlane:
        return RepoShieldControlPlane(self.repo_root, audit=self.audit, policy_config=self.policy_config)

    def handle_chat_completion(self, request: dict[str, Any]) -> dict[str, Any]:
        cp = self._new_request_control_plane()
        self.cp = cp
        lowerer = InstructionLowerer(cp.parser)
        trace = GatewayTrace(trace_id=str(request.get("trace_id") or new_id("gw_trace")))
        messages = extract_messages(request)
        turn_id = trace.new_turn("chat_completion", {"model": request.get("model"), "message_count": len(messages)})
        cp.audit.append("gateway_pre_call", {"trace_id": trace.trace_id, "turn_id": turn_id, "model": request.get("model"), "message_count": len(messages), "request_hash": sha256_json(request)}, actor="gateway")

        cp.build_contract(str(request.get("task") or latest_user_text(messages) or "general code maintenance task"))
        contexts = self._ingest_contexts(request, cp)
        source_ids = [c["source_id"] for c in contexts]
        tool_mappings = self._introspect_request_tools(request)
        if tool_mappings:
            cp.audit.append(
                "tool_mappings_introspected",
                {"trace_id": trace.trace_id, "turn_id": turn_id, "mapping_count": len(tool_mappings), "tools": [m.tool_name for m in tool_mappings]},
                task_id=cp.contract.task_id if cp.contract else None,
                actor="tool_introspector",
            )

        upstream_contexts = [{"source_id": sid, "content": c.get("content", "")} for sid, c in zip(source_ids, contexts)]
        if request.get("stream") and hasattr(self.upstream, "complete_streaming"):
            assistant_msg = self.upstream.complete_streaming(request, contexts=upstream_contexts)
        else:
            assistant_msg = self.upstream.complete(request, contexts=upstream_contexts)
        cp.audit.append("gateway_post_call", {"trace_id": trace.trace_id, "turn_id": turn_id, "assistant_hash": sha256_json(assistant_msg), "tool_call_count": len(assistant_msg.get("tool_calls", []) or [])}, task_id=cp.contract.task_id if cp.contract else None, actor="gateway")

        trust_floor = "untrusted" if source_ids else "trusted"
        builder = InstructionBuilder(trace_id=trace.trace_id, registry=self.registry)
        instructions = builder.response_to_instructions(assistant_msg, turn_id=turn_id, source_ids=source_ids, agent_type=self.agent_type, trust_floor=trust_floor)  # type: ignore[arg-type]

        guarded: list[dict[str, Any]] = []
        for ins in instructions:
            cp.audit.append("instruction_ir", instruction_to_dict(ins), task_id=cp.contract.task_id if cp.contract else None, actor="instruction_builder", source_ids=ins.source_ids)
            action = lowerer.lower(ins, cwd=self.repo_root)
            if not action:
                continue
            action2, decision = cp.guard_action_ir(action)
            runtime = self.policy_runtime.apply(decision)
            item = {"instruction": instruction_to_dict(ins), "action": asdict(action2), "decision": asdict(decision), "runtime": runtime.to_dict()}
            if runtime.effective_decision in {"block", "quarantine", "sandbox_then_approval"}:
                assert cp.contract is not None
                plan = {"trace_id": trace.trace_id, "instructions": [instruction_to_dict(i) for i in instructions]}
                approval = self.approvals.create_request(cp.contract, action2, decision, cp.provenance.graph, plan=plan)
                self.approval_store.append_request(approval)
                approval_payload = asdict(approval)
                item["approval_request"] = approval_payload
                item["confirmation_request"] = approval_payload
                cp.audit.append("gateway_approval_request", approval_payload, task_id=cp.contract.task_id if cp.contract else None, actor="gateway", source_ids=action2.source_ids, action_id=action2.action_id)
            cp.audit.append("policy_runtime", runtime.to_dict(), task_id=cp.contract.task_id if cp.contract else None, actor="policy_runtime", source_ids=action2.source_ids, action_id=action2.action_id, decision_id=decision.decision_id)
            guarded.append(item)

        response = transform_response(assistant_msg, guarded, trace.trace_id, model=str(request.get("model") or "reposhield/local"), release_mode=self.release_mode)
        result = {"trace_id": trace.trace_id, "turn_id": turn_id, "response": response, "instructions": [instruction_to_dict(i) for i in instructions], "guarded_results": guarded, "audit_log": str(cp.audit.log_path)}
        cp.audit.append("gateway_response", {"trace_id": trace.trace_id, "turn_id": turn_id, "blocked_count": sum(1 for g in guarded if g.get("runtime", {}).get("effective_decision") in {"block", "quarantine", "sandbox_then_approval"}), "response_hash": sha256_json(response)}, task_id=cp.contract.task_id if cp.contract else None, actor="gateway")
        return result

    def _introspect_request_tools(self, request: dict[str, Any]):
        mappings = []
        if isinstance(request.get("tools"), list):
            mappings.extend(self.registry.introspect_openai_tools(request["tools"], source="gateway_request.tools"))
        metadata = request.get("metadata") or {}
        manifests = metadata.get("mcp_manifests") or request.get("mcp_manifests") or []
        for manifest in manifests if isinstance(manifests, list) else [manifests]:
            if isinstance(manifest, dict):
                mappings.extend(self.registry.introspect_mcp_manifest(manifest, source="gateway_request.mcp_manifest"))
        agent_config = metadata.get("agent_config") or request.get("agent_config")
        if isinstance(agent_config, dict):
            mappings.extend(self.registry.introspect_agent_config(agent_config, source="gateway_request.agent_config"))
        return mappings

    def _ingest_contexts(self, request: dict[str, Any], cp: RepoShieldControlPlane) -> list[dict[str, Any]]:
        metadata = request.get("metadata") or {}
        raw_contexts = metadata.get("contexts") or request.get("contexts") or []
        contexts: list[dict[str, Any]] = []
        for idx, ctx in enumerate(raw_contexts):
            if isinstance(ctx, str):
                ctx = {"source_type": "external_text", "content": ctx, "source_id": f"src_gateway_ctx_{idx+1:03d}"}
            content = str(ctx.get("content") or "")
            source_type = str(ctx.get("source_type") or ctx.get("type") or "external_text")
            source_id = str(ctx.get("source_id") or f"src_gateway_ctx_{idx+1:03d}")
            src = cp.ingest_source(source_type, content, retrieval_path=str(ctx.get("retrieval_path") or "gateway_context"), source_id=source_id)
            contexts.append({"source_id": src.source_id, "source_type": source_type, "content": content})
        return contexts


def simulate_gateway_request(repo_root: str | Path, request: dict[str, Any], audit_path: str | Path | None = None, policy_mode: str = "enforce") -> dict[str, Any]:
    gw = RepoShieldGateway(repo_root, audit_path=audit_path, policy_mode=policy_mode, unsafe_allow_disabled_policy=bool(request.get("unsafe_allow_disabled_policy")))
    return gw.handle_chat_completion(request)


def make_upstream(
    upstream_base_url: str | None = None,
    upstream_api_key: str | None = None,
    *,
    upstream_chat_path: str = "/chat/completions",
    upstream_timeout: float = 60.0,
) -> Any:
    if upstream_base_url:
        return OpenAICompatibleUpstream(
            base_url=upstream_base_url,
            api_key=upstream_api_key,
            chat_path=upstream_chat_path,
            timeout=upstream_timeout,
        )
    return LocalHeuristicUpstream()


def serve_gateway(
    repo_root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    audit_path: str | Path | None = None,
    policy_mode: str = "enforce",
    upstream_base_url: str | None = None,
    upstream_api_key: str | None = None,
    upstream_chat_path: str = "/chat/completions",
    upstream_timeout: float = 60.0,
    policy_config: str | Path | None = None,
    gateway_api_key: str | None = None,
    release_mode: str = "gateway_only",
    unsafe_allow_disabled_policy: bool = False,
) -> None:
    """Start a tiny standard-library OpenAI-compatible HTTP server.

    Routes: POST /v1/chat/completions and POST /v1/responses.  This is intended
    for local demos and integration tests; production can wrap RepoShieldGateway
    in FastAPI/LiteLLM or another server without changing the gateway core.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    if policy_mode == "disabled" and host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Refusing to run disabled policy mode on a non-loopback gateway host.")
    gateway = RepoShieldGateway(
        repo_root,
        audit_path=audit_path,
        policy_mode=policy_mode,
        policy_config=policy_config,
        release_mode=release_mode,
        unsafe_allow_disabled_policy=unsafe_allow_disabled_policy,
        upstream=make_upstream(
            upstream_base_url=upstream_base_url,
            upstream_api_key=upstream_api_key,
            upstream_chat_path=upstream_chat_path,
            upstream_timeout=upstream_timeout,
        ),
    )
    required_gateway_key = gateway_api_key if gateway_api_key is not None else os.getenv("REPOSHIELD_GATEWAY_API_KEY", "reposhield-local")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        gateway.cp.audit.append("gateway_network_exposure_warning", {"host": host, "requires_authorization": True}, actor="gateway")
        print("RepoShield warning: gateway is listening on a non-loopback host; Authorization is required.", flush=True)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path not in {"/v1/chat/completions", "/v1/responses"}:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            if required_gateway_key and self.headers.get("Authorization") != f"Bearer {required_gateway_key}":
                gateway.cp.audit.append("rejected_gateway_request", {"path": self.path, "reason": "missing_or_invalid_authorization"}, actor="gateway")
                self.send_response(401)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(b'{"error":"missing or invalid Authorization bearer token"}')
                return
            try:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
                request = json.loads(body.decode("utf-8") or "{}")
                result = gateway.handle_chat_completion(request)
                payload = result["response"]
                if self.path == "/v1/responses":
                    payload = responses_api_response(payload, str(result["trace_id"]))
                payload["reposhield"] = {"trace_id": result["trace_id"], "audit_log": result["audit_log"], "guarded_results": result["guarded_results"]}
                if request.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.send_header("X-RepoShield-Trace-Id", str(result["trace_id"]))
                    self.send_header("X-RepoShield-Audit-Log", str(result["audit_log"]))
                    self.end_headers()
                    for event in chat_completion_stream_events(payload):
                        self.wfile.write(event)
                        self.wfile.flush()
                    return
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as exc:  # pragma: no cover - demo server only
                gateway.cp.audit.append(
                    "gateway_error",
                    {"path": self.path, "error_type": type(exc).__name__, "detail": str(exc)},
                    actor="gateway",
                )
                data = json.dumps(
                    {"error": {"type": "upstream_error", "message": "upstream request failed"}},
                    ensure_ascii=False,
                ).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        def log_message(self, _format: str, *args: object) -> None:  # quiet local demo server
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()
