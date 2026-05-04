"""Lower InstructionIR tool calls to ActionIR."""
from __future__ import annotations

from pathlib import Path

from ..action_parser import ActionParser
from ..models import ActionIR
from .schema import InstructionIR


class InstructionLowerer:
    def __init__(self, parser: ActionParser | None = None) -> None:
        self.parser = parser or ActionParser()

    def lower(self, instruction: InstructionIR, cwd: str | Path = ".") -> ActionIR | None:
        if instruction.kind != "tool_call":
            return None
        parse = instruction.metadata.get("tool_parse") or instruction.raw.get("parsed") or {}
        raw_action = str(parse.get("raw_action") or instruction.raw)
        tool = str(parse.get("tool") or "Bash")
        operation = parse.get("operation")
        file_path = parse.get("file_path")
        action = self.parser.parse(raw_action, tool=tool, cwd=cwd, source_ids=instruction.source_ids, operation=operation, file_path=file_path)
        instruction.lowered_action_ir_id = action.action_id
        action.metadata["instruction_id"] = instruction.instruction_id
        action.metadata["trace_id"] = instruction.trace_id
        action.metadata["instruction_hash"] = instruction.instruction_hash
        action.metadata["canonical_tool"] = parse.get("canonical_tool")
        action.parser_confidence = min(action.parser_confidence, float(parse.get("parser_confidence") or instruction.parser_confidence or action.parser_confidence))
        return action
