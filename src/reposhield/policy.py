"""Risk scoring and policy decisions.

Compatibility entrypoint: the implementation now lives in
``reposhield.policy_engine`` so callers can keep importing
``reposhield.policy.PolicyEngine``.
"""
from __future__ import annotations

from .policy_engine.engine import PolicyEngine
from .policy_engine.legacy import LegacyPolicyEngine

__all__ = ["PolicyEngine", "LegacyPolicyEngine"]
