"""Replay-bundle validation."""
from __future__ import annotations

from pathlib import Path
from .audit import AuditLog


def verify_bundle(bundle_dir: str | Path) -> tuple[bool, list[str]]:
    bundle = Path(bundle_dir)
    log = bundle / "audit.jsonl"
    if not log.exists():
        return False, ["audit.jsonl missing"]
    audit = AuditLog(log)
    ok, errors = audit.verify()
    if not (bundle / "replay_spec.json").exists():
        errors.append("replay_spec.json missing")
    if not (bundle / "incident_graph.json").exists():
        errors.append("incident_graph.json missing")
    return ok and not errors, errors
