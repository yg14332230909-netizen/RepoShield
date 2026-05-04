"""Sensitive-information and egress sentinel."""
from __future__ import annotations

import re
from pathlib import Path

from .models import ActionIR, RepoAssetGraph, SecretTaintEvent, new_id, sha256_text

TOKEN_VALUE_RE = re.compile(r"(ghp_[A-Za-z0-9_\-]{10,}|npm_[A-Za-z0-9_\-]{8,}|AKIA[0-9A-Z]{12,}|RS_CANARY_[A-Z0-9_]+)")
SECRET_ENV_NAME_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PRIVATE_KEY|ACCESS_KEY|API_KEY|AUTH)", re.I)


class SecretSentry:
    def __init__(self, asset_graph: RepoAssetGraph):
        self.asset_graph = asset_graph
        self.session_secret_tainted = False
        self.touched_assets: list[str] = []

    def observe_action(self, action: ActionIR) -> SecretTaintEvent | None:
        if action.semantic_action == "read_secret_file":
            asset = action.affected_assets[0] if action.affected_assets else "secret"
            self.session_secret_tainted = True
            self.touched_assets.append(asset)
            return SecretTaintEvent(
                secret_event_id=new_id("sec"),
                event="secret_read_attempt",
                asset=asset,
                actor=action.action_id,
                decision="blocked",
                explanation="Sensitive file access is hard-denied by RepoShield.",
                secret_hash=None,
            )
        if action.semantic_action == "send_network_request" and self.session_secret_tainted:
            target = action.affected_assets[0] if action.affected_assets else "network"
            return SecretTaintEvent(
                secret_event_id=new_id("sec"),
                event="egress_after_secret",
                asset=",".join(self.touched_assets) or "secret",
                actor=action.action_id,
                followed_by="network_request",
                egress_target=target,
                decision="blocked",
                explanation="A prior action touched a sensitive asset; the session is in no-egress mode.",
            )
        if TOKEN_VALUE_RE.search(action.raw_action):
            token = TOKEN_VALUE_RE.search(action.raw_action).group(1)  # type: ignore[union-attr]
            return SecretTaintEvent(
                secret_event_id=new_id("sec"),
                event="token_like_value_in_tool_args",
                asset="inline_secret",
                actor=action.action_id,
                followed_by="tool_args",
                egress_target=action.affected_assets[0] if action.affected_assets else None,
                decision="blocked" if action.semantic_action == "send_network_request" else "quarantine",
                explanation="A token-like value appeared in tool arguments; value is redacted and only a hash is logged.",
                secret_hash=sha256_text(token),
            )
        return None

    def redact(self, text: str) -> str:
        redacted = TOKEN_VALUE_RE.sub("<REDACTED_TOKEN>", text)
        redacted = re.sub(r"(?i)(password|token|secret|api_key)=([^\s&]+)", r"\1=<REDACTED>", redacted)
        return redacted

    def is_sensitive_env_name(self, name: str) -> bool:
        return bool(SECRET_ENV_NAME_RE.search(name))
