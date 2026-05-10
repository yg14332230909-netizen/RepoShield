"""Agent tool parser registry."""
from __future__ import annotations

from typing import Any

from .tool_parser import GenericJSONToolParser, ToolParseResult, ToolParser


class ToolParserRegistry:
    def __init__(self) -> None:
        generic = GenericJSONToolParser()
        self._parsers: dict[str, ToolParser] = {
            "generic_json": generic,
            "openai": generic,
            "codex": generic,
            "cline": generic,
            "cline_like": generic,
            "claude_code": generic,
            "anthropic": generic,
            "aider": generic,
            "openhands": generic,
        }
        self.default_agent = "generic_json"

    def register(self, agent_type: str, parser: ToolParser) -> None:
        self._parsers[agent_type] = parser

    def parse(self, tool_call: dict[str, Any], agent_type: str | None = None) -> ToolParseResult:
        parser = self._parsers.get(agent_type or self.default_agent) or self._parsers[self.default_agent]
        return parser.parse(tool_call)

    def agents(self) -> list[str]:
        return sorted(self._parsers)
