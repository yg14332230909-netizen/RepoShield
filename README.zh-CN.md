# RepoShield / PepoShield v0.3

RepoShield 是面向 coding agent 的执行前安全治理网关。它拦在模型 API、tool call、shell、文件操作、MCP 工具和包管理器动作之前，把代理即将执行的行为转成结构化 `ActionIR`，再结合任务边界、来源可信度、资产类型、密钥事件、供应链信号、沙箱预检和策略图谱，决定动作是放行、仅沙箱执行、需要审批，还是直接阻断。

一句话：

```text
RepoShield = coding agent 的 pre-execution safety gate
```

## 当前成熟度

RepoShield 目前是 **强化后的研究原型 / 早期工程 MVP**。它适合论文演示、课程项目、内部实验、网关拦截研究和有限本地试用，但还不是可以直接商用交付的安全产品。

| 场景 | 当前程度 |
| --- | --- |
| 论文 demo / 项目展示 | 85% - 90% |
| 内部实验平台 | 75% - 85% |
| 小团队本地试用 | 55% - 65% |
| 商业安全产品 | 30% - 40% |

最近本地验证：

```text
pytest -q --basetemp=.pytest_tmp_run         -> 124 passed
python -m compileall -q src tests            -> passed
ruff check src tests                         -> passed
cd web/studio && npm run build               -> passed
```

## 核心创新点

项目最大的创新点是 **多源证据综合判断引擎**。RepoShield 不是只看工具名或黑名单，而是把多个证据源统一成事实，再通过 PolicyGraph 和 RuleIndex 形成可解释决策：

```text
Evidence -> Facts -> RuleIndex -> PolicyGraph -> Decision
```

关键能力包括：

- `FactKeyRegistry`：声明哪些事实可以安全参与索引，例如动作语义、来源可信度、任务边界、资产类型、依赖来源、沙箱观察。
- `FactNormalizer`：把布尔、枚举、列表、数值区间统一成稳定索引键。
- `RuleIndex`：用单事实命中、组合证据命中、残余规则兜底和保守安全剪枝缩小候选规则。
- `PolicyGraph`：把不变量、领域规则、基线风险和决策格合并为最终结论。
- Studio 前端：展示事实矩阵、规则候选缩小过程、谓词命中、证据图谱、沙箱证据和审批状态。

详见：[PolicyGraph / RuleIndex 多源证据引擎](docs/POLICYGRAPH_RULEINDEX.zh-CN.md)。

## 已完成能力

- OpenAI-compatible Gateway，支持 `/v1/chat/completions` 和最小 `/v1/responses` shape
- Gateway bearer token 认证，非 loopback 暴露时强制令牌
- 每个请求隔离 `TaskContract`、`ContextGraph`、`SecretSentry`
- 统一决策语义：`allow`、`allow_in_sandbox`、`sandbox_then_approval`、`block`
- OpenAI、Anthropic、Cline、OpenClaw、OpenHands、Aider parser mapping
- ToolIntrospector / ToolMappingRegistry，自动推断 OpenAI tools、MCP manifests 和 agent config
- transcript provenance，支持 `SOURCE:`、JSONL action、`source_ids=...`
- strict transcript mode，未知可执行行 fail-closed
- compound command lowering，逐段治理复合 shell 命令
- 文件路径 canonicalize，处理 traversal、symlink、隐藏敏感文件
- SecretSentry，覆盖 secret read、egress-after-secret、token-like output、tainted file upload
- PackageGuard，覆盖包管理器解析、依赖来源、lockfile evidence、本地 metadata/provenance oracle
- MCPProxy 和 MemoryStore gate 集成控制面
- SandboxRunner dry-run / overlay / preflight，并输出隔离能力标记
- PolicyGraph / RuleIndex 多源证据检索、候选规则缩小和可解释 trace
- ApprovalCenter / ApprovalStore，稳定 action hash、request/grant/deny JSONL
- AuditLog hash-chain、schema version、replay evidence validation
- Studio Pro 实时仪表盘，包含运行时间线、攻击演示、证据图谱、策略调试、审批中心、沙箱证据、评测报告、记录清空和可选备份
- Stage2 / Stage3 bench、gateway bench、baseline / ablation 报告框架

## 快速开始

安装测试依赖：

```bash
python -m pip install -e ".[test]"
```

启动 Gateway：

```bash
export OPENAI_API_KEY=sk-...

PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./your-repo \
  --host 127.0.0.1 \
  --port 8765 \
  --upstream-base-url https://api.openai.com/v1
```

让 agent 指向：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

启动实时 Studio Pro：

```bash
PYTHONPATH=src python -m reposhield studio-server \
  --audit .reposhield/gateway_audit.jsonl \
  --approvals .reposhield/gateway_approvals.jsonl \
  --host 127.0.0.1 \
  --port 8780 \
  --demo-mode
```

打开：

```text
http://127.0.0.1:8780
```

Studio 会通过 `/api/events/stream` 自动接收真实 Gateway 事件，OpenClaw / OpenHands / Aider 等 agent 经过 RepoShield 后，新动作会自动出现在运行列表和时间线里。

## OpenClaw 接入

生成 OpenClaw provider 和启动脚本：

```bash
PYTHONPATH=src python -m reposhield openclaw-quickstart \
  --repo ./your-repo \
  --reposhield-home . \
  --model gpt-4.1
```

OpenClaw 侧只需要配置本地 RepoShield 地址：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
```

真实上游模型密钥只放在 RepoShield Gateway 进程里，不直接交给 OpenClaw。

## 决策语义

| decision | 语义 |
| --- | --- |
| `allow` | 可以在宿主机执行 |
| `allow_in_sandbox` | 只能在 sandbox / overlay / preflight 中执行，不能直接在宿主机执行 |
| `sandbox_then_approval` | 不执行，生成审批请求或等待人工确认 |
| `block` / `quarantine` | 不执行 |

## 仍需加强

- 生产级 sandbox：container、Linux namespace、seccomp/eBPF、网络监控等
- 真实供应链情报：npm/PyPI metadata、tarball inspection、Sigstore、typosquatting、maintainer reputation
- 更大规模真实 agent trace 兼容测试
- 策略签名、租户策略、团队权限、API key rotation
- Studio 的长期存储、跨项目搜索、多租户视图和团队协作能力
- 更多真实样本上的误报、漏报和 ablation 指标

## 文档入口

建议阅读顺序：

1. [文档目录](docs/README.zh-CN.md)
2. [PolicyGraph / RuleIndex 多源证据引擎](docs/POLICYGRAPH_RULEINDEX.zh-CN.md)
3. [Studio 指南](docs/STUDIO_GUIDE.zh-CN.md)
4. [真实 Agent 接入指南](docs/REAL_AGENT_INTEGRATION.zh-CN.md)
5. [Gateway 指南](docs/GATEWAY_GUIDE.zh-CN.md)
6. [Policy Pack 指南](docs/POLICY_PACK_GUIDE.zh-CN.md)
7. [项目状态与商用化评估](docs/PROJECT_STATUS.zh-CN.md)
