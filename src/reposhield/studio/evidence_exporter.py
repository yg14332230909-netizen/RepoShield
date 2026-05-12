"""Export redacted Studio evidence bundles."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .event_stream import StudioEventIndex
from .redaction import redact_value


def export_evidence(index: StudioEventIndex, run_id: str, output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    events = index.events(run_id=run_id, limit=10000)
    graph = index.graph(run_id)
    actions = [e for e in events if e.get("type") == "action_parsed"]
    decisions = [e for e in events if e.get("type") == "policy_decision"]
    (out / "events.jsonl").write_text("\n".join(json.dumps(redact_value(e), ensure_ascii=False, sort_keys=True) for e in events) + ("\n" if events else ""), encoding="utf-8")
    (out / "actions.json").write_text(json.dumps(redact_value(actions), ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "decisions.json").write_text(json.dumps(redact_value(decisions), ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "graph.json").write_text(json.dumps(redact_value(graph), ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "summary.md").write_text(_summary(run_id, events, decisions), encoding="utf-8")
    return out


def _summary(run_id: str, events: list[dict[str, Any]], decisions: list[dict[str, Any]]) -> str:
    blocked = [d for d in decisions if d.get("payload", {}).get("decision") in {"block", "quarantine", "sandbox_then_approval"}]
    lines = [
        f"# RepoShield Evidence Bundle: {run_id}",
        "",
        f"- Events: {len(events)}",
        f"- Policy decisions: {len(decisions)}",
        f"- Blocking decisions: {len(blocked)}",
        "",
        "## Decisions",
    ]
    for d in decisions:
        p = d.get("payload", {})
        lines.append(f"- `{p.get('decision')}` `{p.get('semantic_action', p.get('action_id', 'action'))}` reasons={p.get('reason_codes', [])}")
    return "\n".join(lines) + "\n"
