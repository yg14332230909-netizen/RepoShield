"""OpenAI-compatible request/response helpers."""
from __future__ import annotations

import json
import re
from typing import Any

from ..models import new_id, utc_now


def extract_messages(request: dict[str, Any]) -> list[dict[str, Any]]:
    if "messages" in request and isinstance(request["messages"], list):
        return request["messages"]
    if "input" in request:
        inp = request["input"]
        if isinstance(inp, str):
            return [{"role": "user", "content": inp}]
        if isinstance(inp, list):
            return inp
    return []


def latest_user_text(messages: list[dict[str, Any]]) -> str:
    for msg in reversed(messages):
        if msg.get("role") == "user":
            return str(msg.get("content") or "")
    return "general code maintenance task"


def assistant_message_response(message: dict[str, Any], model: str = "reposhield/local") -> dict[str, Any]:
    return {
        "id": new_id("chatcmpl"),
        "object": "chat.completion",
        "created": utc_now(),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def chat_completion_stream_events(response: dict[str, Any]) -> list[bytes]:
    """Encode a non-stream chat completion as OpenAI-compatible SSE events.

    The gateway still performs policy checks on a complete assistant message, then
    emits a standards-shaped stream for agents that require `stream=true`.
    """
    model = str(response.get("model") or "reposhield/local")
    message = ((response.get("choices") or [{}])[0].get("message") or {}) if isinstance(response.get("choices"), list) else {}
    finish_reason = ((response.get("choices") or [{}])[0].get("finish_reason") or "stop") if isinstance(response.get("choices"), list) else "stop"
    stream_id = str(response.get("id") or new_id("chatcmpl"))
    created = response.get("created") or utc_now()
    events: list[dict[str, Any]] = [
        {
            "id": stream_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
        }
    ]

    content = str(message.get("content") or "")
    for chunk in _content_chunks(content):
        events.append(
            {
                "id": stream_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": None}],
            }
        )

    tool_calls = message.get("tool_calls") or []
    for index, tool_call in enumerate(tool_calls):
        chunk_call: dict[str, Any] = {"index": index}
        if tool_call.get("id"):
            chunk_call["id"] = tool_call["id"]
        if tool_call.get("type"):
            chunk_call["type"] = tool_call["type"]
        function = tool_call.get("function") or {}
        if function:
            chunk_call["function"] = {
                key: value
                for key, value in {
                    "name": function.get("name"),
                    "arguments": function.get("arguments"),
                }.items()
                if value is not None
            }
        events.append(
            {
                "id": stream_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {"tool_calls": [chunk_call]}, "finish_reason": None}],
            }
        )

    events.append(
        {
            "id": stream_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
        }
    )
    return [f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8") for event in events] + [b"data: [DONE]\n\n"]


def _content_chunks(content: str, size: int = 256) -> list[str]:
    if not content:
        return []
    return [content[i:i + size] for i in range(0, len(content), size)]


def safe_block_message(reason: str, decisions: list[dict[str, Any]], trace_id: str) -> dict[str, Any]:
    lines = ["RepoShield blocked or constrained a high-risk tool call before execution.", f"trace_id={trace_id}", ""]
    for d in decisions:
        action = d.get("action", {})
        dec = d.get("decision", {})
        lines.append(f"- action: {_redact_secret_text(action.get('raw_action'))}")
        lines.append(f"  semantic: {action.get('semantic_action')}")
        lines.append(f"  decision: {dec.get('decision')} risk={dec.get('risk_score')}")
        lines.append(f"  reasons: {', '.join(dec.get('reason_codes', []))}")
    lines.append("")
    lines.append("Allowed approval grants: deny, allow_once_sandbox_only, allow_once_no_network, allow_once_no_lifecycle.")
    return {"role": "assistant", "content": reason + "\n" + "\n".join(lines), "tool_calls": []}


def safe_sandbox_only_message(reason: str, decisions: list[dict[str, Any]], trace_id: str) -> dict[str, Any]:
    lines = ["RepoShield constrained a tool call to sandbox-only handling.", f"trace_id={trace_id}", ""]
    for d in decisions:
        action = d.get("action", {})
        dec = d.get("decision", {})
        lines.append(f"- action: {_redact_secret_text(action.get('raw_action'))}")
        lines.append(f"  semantic: {action.get('semantic_action')}")
        lines.append(f"  decision: {dec.get('decision')} risk={dec.get('risk_score')}")
        lines.append("  host_execution: denied")
        lines.append("  next_step: run only through RepoShield sandbox, overlay, or preflight tooling")
    return {"role": "assistant", "content": reason + "\n" + "\n".join(lines), "tool_calls": []}


def _redact_secret_text(value: Any) -> str:
    text = str(value or "")
    token_re = re.compile(r"(ghp_[A-Za-z0-9_\-]{10,}|npm_[A-Za-z0-9_\-]{8,}|RS_CANARY_[A-Z0-9_]+)")
    kv_re = re.compile(r"(?i)(password|token|secret|api_key)=([^\s&]+)")
    bearer_re = re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)[^\s'\"]+")
    text = token_re.sub("<REDACTED_TOKEN>", text)
    text = kv_re.sub(r"\1=<REDACTED>", text)
    text = bearer_re.sub(r"\1<REDACTED>", text)
    return text
