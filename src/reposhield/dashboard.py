"""Minimal local HTML dashboard renderer."""
from __future__ import annotations

import html
import json
from pathlib import Path

from .audit import AuditLog


def render_dashboard(audit_path: str | Path, output_path: str | Path, approvals_path: str | Path | None = None) -> Path:
    audit = AuditLog(audit_path)
    events = audit.read_events()
    approvals = _read_jsonl(approvals_path) if approvals_path else []
    blocked = [
        e for e in events
        if e.get("event_type") == "policy_decision"
        and e.get("payload", {}).get("decision") in {"block", "quarantine", "sandbox_then_approval"}
    ]
    rows = []
    for event in blocked[-50:]:
        payload = event.get("payload", {})
        rows.append(
            "<tr>"
            f"<td>{html.escape(event.get('timestamp', ''))}</td>"
            f"<td>{html.escape(str(payload.get('decision', '')))}</td>"
            f"<td>{html.escape(str(payload.get('risk_score', '')))}</td>"
            f"<td>{html.escape(', '.join(payload.get('reason_codes', [])))}</td>"
            f"<td><code>{html.escape(str(event.get('action_id') or ''))}</code></td>"
            "</tr>"
        )
    approval_rows = []
    for item in approvals[-50:]:
        payload = item.get("payload", {})
        approval_rows.append(
            "<tr>"
            f"<td>{html.escape(item.get('created_at', ''))}</td>"
            f"<td>{html.escape(item.get('event_type', ''))}</td>"
            f"<td>{html.escape(str(payload.get('approval_request_id') or payload.get('approval_id') or ''))}</td>"
            f"<td>{html.escape(str(payload.get('action_id') or ''))}</td>"
            "</tr>"
        )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>RepoShield Dashboard</title>
<style>body{{font-family:system-ui;margin:32px;line-height:1.45}}.card{{border:1px solid #d0d7de;border-radius:8px;padding:16px;margin:16px 0}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #d0d7de;padding:8px;vertical-align:top}}th{{background:#f6f8fa}}code{{background:#f6f8fa;padding:2px 4px;border-radius:4px}}</style>
</head><body>
<h1>RepoShield Dashboard</h1>
<div class="card"><strong>Audit:</strong> {html.escape(str(audit_path))}<br><strong>Events:</strong> {len(events)}<br><strong>Blocked / approval-required:</strong> {len(blocked)}</div>
<h2>Recent Policy Blocks</h2>
<table><thead><tr><th>time</th><th>decision</th><th>risk</th><th>reasons</th><th>action</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>Approval Events</h2>
<table><thead><tr><th>time</th><th>type</th><th>approval</th><th>action</th></tr></thead><tbody>{''.join(approval_rows)}</tbody></table>
</body></html>"""
    out.write_text(doc, encoding="utf-8")
    return out


def _read_jsonl(path: str | Path | None) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    rows = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

