# RepoShield / PepoShield v0.3

RepoShield 是一个面向 coding agent 的执行前安全治理网关。它放在真实智能体和模型 API / 工具执行链路之间，在智能体运行命令、改文件、安装依赖、访问网络或调用工具之前，先判断这一步是否符合任务、来源是否可信、是否会触碰密钥、供应链、CI/CD 或发布边界。

一句话：

```text
RepoShield = 给代码智能体加一道“执行前安检门”
```

## 它插在哪里

推荐接入方式是 OpenAI-compatible Gateway：

```text
真实 agent
  -> RepoShield Gateway
  -> 真实 upstream model
  -> assistant message / tool_calls
  -> RepoShield 治理 tool_calls
  -> 安全响应返回给 agent
```

支持自定义 `base_url` 的 agent 通常不需要改代码，只要把模型地址改成 RepoShield 本地网关：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

启动 RepoShield 并转发到真实模型 API：

```bash
export OPENAI_API_KEY=sk-...

PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./your-repo \
  --host 127.0.0.1 \
  --port 8765 \
  --upstream-base-url https://api.openai.com/v1
```

## 当前能做什么

- OpenAI-compatible `/v1/chat/completions` 和 `/v1/responses` Gateway
- 真实 OpenAI-compatible upstream 转发
- upstream SSE 聚合，然后对完整 tool calls 做治理
- agent 侧 `stream=true` 的 OpenAI-compatible SSE 响应
- `exec-guard`：把真实 shell 命令包进 RepoShield
- `file-guard`：在文件 read/write/edit/delete 前做治理
- `init-agent`：一键生成 repo-local 配置、agent 说明和 PATH shims
- `approvals`：JSONL 持久化审批 list / approve / deny 闭环
- JSON/YAML policy override
- 本地 HTML dashboard
- InstructionIR / ActionIR / TaskContract / source trust / policy runtime
- package supply-chain guard、secret read / egress sentinel、sandbox preflight
- hash-chain audit log、incident report、Gateway Bench、Studio report
- CI workflow 和 ruff lint 配置

## 快速开始

安装和测试：

```bash
python -m pip install -e ".[test]"
pytest -q --basetemp .pytest_tmp
```

一键初始化某个真实项目：

```bash
PYTHONPATH=src python -m reposhield init-agent \
  --repo ./your-repo \
  --agent cline \
  --task "fix login and run tests"
```

它会生成：

```text
your-repo/.reposhield/config.json
your-repo/.reposhield/agent-instructions.md
your-repo/.reposhield/shims/{npm,git,curl,python}
your-repo/.reposhield/shims/{npm,git,curl,python}.ps1
```

这些 shim 可以把常用命令导到：

```bash
PYTHONPATH=src python -m reposhield exec-guard --repo ./your-repo --task "..." -- npm test
```

## 常用命令

```text
reposhield init-agent          生成 agent 接入配置、说明和 shims
reposhield gateway-start       启动 OpenAI-compatible Gateway
reposhield gateway-simulate    用 JSON 请求模拟 Gateway
reposhield exec-guard          治理并执行真实 shell 命令
reposhield file-guard          治理文件读写删改动作
reposhield approvals list      查看待处理和历史审批事件
reposhield approvals approve   生成审批授权
reposhield approvals deny      记录审批拒绝
reposhield dashboard           生成本地 HTML dashboard
reposhield guard               对单个动作做安全决策
reposhield parse               把 raw action 转成 ActionIR
reposhield scan                扫描仓库资产和风险面
reposhield gateway-bench       运行 stage3 Gateway bench
reposhield studio              生成 HTML Studio 报告
reposhield audit-verify        验证 hash-chain audit log
```

## Policy YAML 示例

`guard`、`exec-guard`、`file-guard`、`gateway-simulate`、`gateway-start` 都支持 `--policy-config`：

```yaml
rules:
  - name: block_ci_from_issue
    match:
      operation: edit
      file_path: .github/workflows/release.yml
    decision: block
    reason: configured_ci_protection
```

## 当前边界

这个项目现在是“可运行的安全治理 MVP / 研究原型”，还不是成熟生产安全产品。

已经适合：

- 本地 demo
- 小范围真实 agent 试接
- Gateway 拦截链路验证
- shell/file 工具治理实验
- bench、审计和报告演示

仍需补强：

- token-by-token 的真流式透传治理。目前 upstream streaming 会先被聚合成完整 assistant message，再治理，再向 agent 输出 SSE。
- 更完整的 shell parser、编码绕过、脚本间接执行和跨平台命令覆盖。
- 更强 sandbox，例如 container、namespace、seccomp 或 eBPF。
- 针对 Cline、Codex、OpenHands、Claude Code、Aider 的更完整 adapter。
- Web 审批 UI、持久权限记忆、团队策略和集中配置。

## 推荐阅读

1. [真实 Agent 接入指南](docs/REAL_AGENT_INTEGRATION.zh-CN.md)
2. [Cline / Codex / OpenHands 配置示例](docs/AGENT_EXEC_GUARD_RECIPES.zh-CN.md)
3. [文档地图](docs/README.zh-CN.md)
4. [Gateway 指南](docs/GATEWAY_GUIDE.zh-CN.md)
5. [Tool Parser Plugin 指南](docs/TOOL_PARSER_PLUGIN_GUIDE.zh-CN.md)

## 验证状态

```text
pytest -q --basetemp .pytest_tmp -> 40 passed
python -m compileall -q src -> passed
```
