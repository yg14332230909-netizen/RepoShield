# RepoShield Gateway 指南

Gateway 把 RepoShield 插到模型请求和 agent tool execution 之间：

```text
Agent -> OpenAI-compatible request -> RepoShield Gateway -> upstream model
      <- governed safe response <- InstructionIR / ActionIR / Policy / Audit
```

它解决的问题是：真实 agent 往往直接调用 OpenAI-compatible API。Gateway 让这些 agent 只改 `base_url`，就能进入 RepoShield 的治理链路。

## 启动真实 upstream

```bash
export OPENAI_API_KEY=sk-...

PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./demo_repo \
  --host 127.0.0.1 \
  --port 8765 \
  --upstream-base-url https://api.openai.com/v1
```

agent 侧配置：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

没有传 `--upstream-base-url` 时，Gateway 使用本地 deterministic upstream，适合 demo 和测试。

## 处理流程

```text
1. 读取 OpenAI-compatible 请求
2. metadata.contexts -> SourceRecord
3. 构建 TaskContract
4. 调用 upstream
5. assistant message / tool_calls -> InstructionIR
6. InstructionIR -> ActionIR
7. control plane guard_action
8. PolicyRuntime apply
9. block / approval / sandbox / allow
10. 转换成安全响应并写 audit
```

如果 tool call 高危，Gateway 会把响应替换成 RepoShield 的阻断说明，并清空 `tool_calls`，避免下游 agent 继续执行危险动作。

## Streaming

Gateway 支持 agent 侧：

```json
{"stream": true}
```

当前实现分两层：

- upstream 侧：`OpenAICompatibleUpstream.complete_streaming()` 会请求真实 upstream SSE，并在 RepoShield 内部聚合 `delta.content` 和 `delta.tool_calls`。
- agent 侧：治理完成后，Gateway 返回 OpenAI-compatible `text/event-stream`。

这意味着现在已经不是简单强制 upstream `stream=false`；真实 upstream SSE 可以被消费和聚合。但它仍不是 token-by-token 的透传代理，因为 RepoShield 必须先看完整 tool call，才能判断是否要阻断、审批或沙箱。

后续要做完整真流式透传，需要补：

```text
流式 tool_call 聚合 -> 中途策略判断 -> 安全终止响应 -> 审计与回放一致性
```

## Policy 配置

`gateway-start` 和 `gateway-simulate` 支持 `--policy-config`，可用 JSON/YAML 覆盖决策：

```yaml
rules:
  - name: block_ci_from_issue
    match:
      operation: edit
      file_path: .github/workflows/release.yml
    decision: block
    reason: configured_ci_protection
```

启动：

```bash
PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./demo_repo \
  --upstream-base-url https://api.openai.com/v1 \
  --policy-config ./reposhield-policy.yaml
```

## 关键模块

```text
src/reposhield/gateway/app.py                 RepoShieldGateway
src/reposhield/gateway/openai_compat.py       请求/响应兼容层
src/reposhield/gateway/upstream.py            本地 upstream 与真实 OpenAI-compatible upstream
src/reposhield/gateway/response_transform.py  阻断响应转换
src/reposhield/gateway/confirmation_flow.py   Gateway 审批确认请求
src/reposhield/control_plane.py               治理主入口
src/reposhield/policy_config.py               JSON/YAML policy override
```
