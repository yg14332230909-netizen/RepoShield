"""RepoShield OpenAI-compatible Governance Gateway."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from ..control_plane import RepoShieldControlPlane
from ..instruction_ir import InstructionBuilder, InstructionLowerer, to_dict as instruction_to_dict
from ..models import new_id, sha256_json
from ..plugins import ToolParserRegistry
from ..policy_runtime import PolicyRuntime
from .confirmation_flow import GatewayConfirmationFlow
from .openai_compat import chat_completion_stream_events, extract_messages, latest_user_text
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
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.cp = RepoShieldControlPlane(self.repo_root, audit_path=audit_path or self.repo_root / ".reposhield" / "gateway_audit.jsonl", policy_config=policy_config)
        self.policy_runtime = PolicyRuntime(mode=policy_mode, role=policy_role)  # type: ignore[arg-type]
        self.upstream = upstream or LocalHeuristicUpstream()
        self.agent_type = agent_type
        self.registry = ToolParserRegistry()
        self.lowerer = InstructionLowerer(self.cp.parser)
        self.confirmations = GatewayConfirmationFlow()

    def handle_chat_completion(self, request: dict[str, Any]) -> dict[str, Any]:
        trace = GatewayTrace(trace_id=str(request.get("trace_id") or new_id("gw_trace")))
        messages = extract_messages(request)
        turn_id = trace.new_turn("chat_completion", {"model": request.get("model"), "message_count": len(messages)})
        self.cp.audit.append("gateway_pre_call", {"trace_id": trace.trace_id, "turn_id": turn_id, "model": request.get("model"), "message_count": len(messages), "request_hash": sha256_json(request)}, actor="gateway")

        contexts = self._ingest_contexts(request)
        source_ids = [c["source_id"] for c in contexts]
        if not self.cp.contract:
            self.cp.build_contract(str(request.get("task") or latest_user_text(messages) or "general code maintenance task"))

        upstream_contexts = [{"source_id": sid, "content": c.get("content", "")} for sid, c in zip(source_ids, contexts)]
        if request.get("stream") and hasattr(self.upstream, "complete_streaming"):
            assistant_msg = self.upstream.complete_streaming(request, contexts=upstream_contexts)
        else:
            assistant_msg = self.upstream.complete(request, contexts=upstream_contexts)
        self.cp.audit.append("gateway_post_call", {"trace_id": trace.trace_id, "turn_id": turn_id, "assistant_hash": sha256_json(assistant_msg), "tool_call_count": len(assistant_msg.get("tool_calls", []) or [])}, task_id=self.cp.contract.task_id if self.cp.contract else None, actor="gateway")

        trust_floor = "untrusted" if source_ids else "trusted"
        builder = InstructionBuilder(trace_id=trace.trace_id, registry=self.registry)
        instructions = builder.response_to_instructions(assistant_msg, turn_id=turn_id, source_ids=source_ids, agent_type=self.agent_type, trust_floor=trust_floor)  # type: ignore[arg-type]

        guarded: list[dict[str, Any]] = []
        for ins in instructions:
            self.cp.audit.append("instruction_ir", instruction_to_dict(ins), task_id=self.cp.contract.task_id if self.cp.contract else None, actor="instruction_builder", source_ids=ins.source_ids)
            action = self.lowerer.lower(ins, cwd=self.repo_root)
            if not action:
                continue
            # Re-use the control-plane pipeline from the raw action so package/sandbox/sentry evidence stays consistent.
            action2, decision = self.cp.guard_action(action.raw_action, source_ids=action.source_ids, tool=action.tool, operation=action.metadata.get("operation"), file_path=action.affected_assets[0] if action.tool.lower() in {"read", "write", "edit", "delete"} and action.affected_assets else None)
            action2.metadata.update(action.metadata)
            runtime = self.policy_runtime.apply(decision)
            item = {"instruction": instruction_to_dict(ins), "action": asdict(action2), "decision": asdict(decision), "runtime": runtime.to_dict()}
            if runtime.effective_decision in {"block", "quarantine", "sandbox_then_approval"}:
                confirm = self.confirmations.create(trace.trace_id, asdict(action2), plan={"instructions": [instruction_to_dict(i) for i in instructions]})
                item["confirmation_request"] = asdict(confirm)
                self.cp.audit.append("gateway_confirmation_request", asdict(confirm), task_id=self.cp.contract.task_id if self.cp.contract else None, actor="gateway", source_ids=action2.source_ids, action_id=action2.action_id)
            self.cp.audit.append("policy_runtime", runtime.to_dict(), task_id=self.cp.contract.task_id if self.cp.contract else None, actor="policy_runtime", source_ids=action2.source_ids, action_id=action2.action_id, decision_id=decision.decision_id)
            guarded.append(item)

        response = transform_response(assistant_msg, guarded, trace.trace_id, model=str(request.get("model") or "reposhield/local"))
        result = {"trace_id": trace.trace_id, "turn_id": turn_id, "response": response, "instructions": [instruction_to_dict(i) for i in instructions], "guarded_results": guarded, "audit_log": str(self.cp.audit.log_path)}
        self.cp.audit.append("gateway_response", {"trace_id": trace.trace_id, "turn_id": turn_id, "blocked_count": sum(1 for g in guarded if g.get("runtime", {}).get("effective_decision") in {"block", "quarantine", "sandbox_then_approval"}), "response_hash": sha256_json(response)}, task_id=self.cp.contract.task_id if self.cp.contract else None, actor="gateway")
        return result

    def _ingest_contexts(self, request: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = request.get("metadata") or {}
        raw_contexts = metadata.get("contexts") or request.get("contexts") or []
        contexts: list[dict[str, Any]] = []
        for idx, ctx in enumerate(raw_contexts):
            if isinstance(ctx, str):
                ctx = {"source_type": "external_text", "content": ctx, "source_id": f"src_gateway_ctx_{idx+1:03d}"}
            content = str(ctx.get("content") or "")
            source_type = str(ctx.get("source_type") or ctx.get("type") or "external_text")
            source_id = str(ctx.get("source_id") or f"src_gateway_ctx_{idx+1:03d}")
            src = self.cp.ingest_source(source_type, content, retrieval_path=str(ctx.get("retrieval_path") or "gateway_context"), source_id=source_id)
            contexts.append({"source_id": src.source_id, "source_type": source_type, "content": content})
        return contexts


def simulate_gateway_request(repo_root: str | Path, request: dict[str, Any], audit_path: str | Path | None = None, policy_mode: str = "enforce") -> dict[str, Any]:
    gw = RepoShieldGateway(repo_root, audit_path=audit_path, policy_mode=policy_mode)
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
) -> None:
    """Start a tiny standard-library OpenAI-compatible HTTP server.

    Routes: POST /v1/chat/completions and POST /v1/responses.  This is intended
    for local demos and integration tests; production can wrap RepoShieldGateway
    in FastAPI/LiteLLM or another server without changing the gateway core.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    gateway = RepoShieldGateway(
        repo_root,
        audit_path=audit_path,
        policy_mode=policy_mode,
        policy_config=policy_config,
        upstream=make_upstream(
            upstream_base_url=upstream_base_url,
            upstream_api_key=upstream_api_key,
            upstream_chat_path=upstream_chat_path,
            upstream_timeout=upstream_timeout,
        ),
    )

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path not in {"/v1/chat/completions", "/v1/responses"}:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            try:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
                request = json.loads(body.decode("utf-8") or "{}")
                result = gateway.handle_chat_completion(request)
                payload = result["response"]
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
                data = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        def log_message(self, _format: str, *args: object) -> None:  # quiet local demo server
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()
