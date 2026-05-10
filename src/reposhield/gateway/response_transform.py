"""Response transformation after policy decisions."""
from __future__ import annotations

from typing import Any

from .openai_compat import assistant_message_response, safe_block_message


def transform_response(original_message: dict[str, Any], guarded_results: list[dict[str, Any]], trace_id: str, model: str = "reposhield/local") -> dict[str, Any]:
    blocked = [r for r in guarded_results if r.get("runtime", {}).get("effective_decision") in {"block", "quarantine", "sandbox_then_approval"}]
    if blocked:
        message = safe_block_message("RepoShield Gateway policy result:", blocked, trace_id)
        return assistant_message_response(message, model=model)
    # Keep tool calls for allowed actions.  In a real runtime, the agent would then execute them through guarded tools.
    return assistant_message_response(original_message, model=model)
