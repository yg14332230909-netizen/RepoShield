"""Preflight planning primitives for PolicyGraph decisions."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PreflightPlan:
    required: bool
    profile: str = "dry-run"
    evidence_mode: str = "summary"
    reason_codes: list[str] = field(default_factory=list)
    required_controls: list[str] = field(default_factory=list)
