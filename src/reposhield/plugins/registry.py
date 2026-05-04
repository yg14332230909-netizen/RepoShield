"""Agent tool parser registry."""
from __future__ import annotations

from typing import Any

from .tool_parser import GenericJSONToolParser, ToolParseResult, ToolParser


class ToolParserRegistry:
    def __init__(self) -> None:
        self._parsers: dict[str, ToolParser] = {"generic_json": GenericJSONToolParser(), "openai": GenericJSONToolParser(), "cline_like": GenericJSONToolParser(), "aider": GenericJSONToolParser()}
        self.default_agent = "generic_json"

    def register(self, agent_type: str, parser: ToolParser) -> None:
        self._parsers[agent_type] = parser

    def parse(self, tool_call: dict[str, Any], agent_type: str | None = None) -> ToolParseResult:
        parser = self._parsers.get(agent_type or self.default_agent) or self._parsers[self.default_agent]
        return parser.parse(tool_call)

    def agents(self) -> list[str]:
        return sorted(self._parsers)
