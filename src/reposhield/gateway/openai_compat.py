"""OpenAI-compatible request/response helpers."""
from __future__ import annotations

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


def safe_block_message(reason: str, decisions: list[dict[str, Any]], trace_id: str) -> dict[str, Any]:
    lines = ["RepoShield blocked or constrained a high-risk tool call before execution.", f"trace_id={trace_id}", ""]
    for d in decisions:
        action = d.get("action", {})
        dec = d.get("decision", {})
        lines.append(f"- action: {action.get('raw_action')}")
        lines.append(f"  semantic: {action.get('semantic_action')}")
        lines.append(f"  decision: {dec.get('decision')} risk={dec.get('risk_score')}")
        lines.append(f"  reasons: {', '.join(dec.get('reason_codes', []))}")
    lines.append("")
    lines.append("Allowed approval grants: deny, allow_once_sandbox_only, allow_once_no_network, allow_once_no_lifecycle.")
    return {"role": "assistant", "content": reason + "\n" + "\n".join(lines), "tool_calls": []}
