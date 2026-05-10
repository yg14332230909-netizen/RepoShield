# RepoShield / PepoShield v0.3

RepoShield 是一个面向 coding agent 的执行前安全治理网关。它拦在模型 API、tool call、shell/file/MCP 工具执行路径之前，把模型提出的动作转换成结构化 `ActionIR`，再结合任务合同、上下文来源、敏感信息、供应链、沙箱预检和策略规则决定是否允许执行。

一句话：

```text
RepoShield = coding agent 的 pre-execution safety gate
```

## 当前成熟度

这个仓库目前处在 **研究原型加强版 / 工程化 MVP 前期**。

它已经不只是演示脚本，主链路、Gateway、审计、策略、approval、sandbox preflight、bench 和 dashboard 都有可运行实现和测试覆盖。但它还不是可直接面向企业客户部署的生产级安全产品。

大致成熟度：

| 场景 | 当前程度 |
| --- | --- |
| 论文 demo / 项目展示 | 85% - 90% |
| 内部实验平台 | 75% - 85% |
| 小团队本地试用 | 55% - 65% |
| 商用化安全产品 | 30% - 40% |

最近验证状态：

```text
python -m pytest --basetemp=.pytest_tmp -q   -> 77 passed
python -m compileall -q src tests            -> passed
ruff check src tests                         -> passed
```

## 已完成的核心能力

- OpenAI-compatible Gateway：支持 `/v1/chat/completions` 和最小 `/v1/responses` shape
- Gateway bearer token 认证，非 loopback 暴露会显式告警
- 每个 Gateway 请求隔离 `TaskContract` / `ContextGraph` / `SecretSentry`
- Gateway-only 模式下不会释放 `allow_in_sandbox` tool call 给裸 agent
- `allow / allow_in_sandbox / sandbox_then_approval / block` 语义已统一
- `guard_action_ir()` 复用同一个 `ActionIR`，避免 lower 后重新 raw parse 丢失语义
- OpenAI / Anthropic / Cline / OpenHands / Aider tool parser mapping
- transcript provenance：支持 `SOURCE:`、JSONL action、`source_ids=...`
- strict transcript mode：未知可执行行 fail-closed
- compound command lowering：`npm test && rm -rf .` 会逐段治理
- 文件路径 canonicalize：处理 traversal / symlink / hidden sensitive file
- SecretSentry：secret read、egress-after-secret、stdout/stderr token、tainted file upload
- PackageGuard：package manager parser、registry 检测、lockfile evidence、本地 metadata/provenance oracle
- MCPProxy：token passthrough / destructive capability gate，结果进入 PolicyEngine
- MemoryStore：tainted memory 不能授权高风险动作
- SandboxRunner：dry-run / overlay preflight，测试命令不使用 `shell=True`
- sandbox profile enforcement matrix，显式标记 `isolation_level` 和 `production_ready`
- PolicyDecision：`policy_version`、`matched_rules`、`evidence_refs`、`rule_trace`
- disabled policy mode 必须显式 unsafe flag，非 loopback Gateway 禁止 disabled
- ApprovalCenter / ApprovalStore：稳定 action hash、request/grant/deny JSONL
- GuardedExecAdapter：host execution started/completed audit，stdout/stderr 脱敏截断和 hash
- AuditLog：线程安全 hash-chain、schema version、基础 event validation
- Replay：hash-chain 与 policy evidence 引用校验
- Dashboard：blocked actions、approval events、evidence chains
- Bench：stage2/stage3 sample suite、gateway bench、baseline/ablation 报告框架

## 主要架构

```text
real agent
  -> RepoShield Gateway / exec-guard / file-guard / PATH shim
  -> ToolParserRegistry
  -> InstructionIR
  -> ActionIR
  -> RepoShieldControlPlane
      -> TaskContract
      -> ContextGraph / provenance
      -> SecretSentry
      -> PackageGuard
      -> MCPProxy / MemoryStore
      -> SandboxRunner
      -> PolicyEngine / PolicyRuntime
      -> ApprovalCenter
      -> AuditLog
  -> allow / allow_in_sandbox / sandbox_then_approval / block
```

## 快速开始

安装测试依赖：

```bash
python -m pip install -e ".[test]"
```

启动 OpenAI-compatible Gateway：

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

包装真实 shell 工具：

```bash
PYTHONPATH=src python -m reposhield exec-guard \
  --repo ./your-repo \
  --task "fix login button and run tests" \
  -- npm test
```

初始化 repo-local agent 配置和 PATH shims：

```bash
PYTHONPATH=src python -m reposhield init-agent \
  --repo ./your-repo \
  --agent cline \
  --task "fix login and run tests"
```

## 决策语义

全项目统一使用下面四类执行语义：

| decision | 语义 |
| --- | --- |
| `allow` | 可以在宿主机执行 |
| `allow_in_sandbox` | 只能在 sandbox / overlay / preflight 中执行，不能在宿主机直接执行 |
| `sandbox_then_approval` | 不执行，生成审批请求或等待人工确认 |
| `block` / `quarantine` | 不执行 |

## 商用化差距

RepoShield 现在适合论文、演示、内部实验和小范围本地试用。要进入商用化，还需要重点补齐：

1. **生产级 sandbox**  
   当前是 dry-run / overlay / proxy preflight。商用需要 bubblewrap、containerd、Linux namespace、seccomp/eBPF、网络 egress monitor 等真实隔离。

2. **真实供应链情报**  
   当前有本地 metadata/provenance oracle。商用需要 npm/PyPI metadata、tarball inspection、Sigstore、typosquatting、maintainer reputation、lockfile diff。

3. **真实 agent 适配和兼容测试**  
   已有 parser mapping，但还需要持续采集 Codex/Cline/OpenHands/Aider 真实 tool traces，做 schema drift 测试。

4. **策略和审批产品化**  
   需要稳定策略语言、策略签名、租户级策略、审批 API/UI、权限模型、API key rotation。

5. **Studio / Dashboard 产品化**  
   当前是本地 HTML evidence view。商用需要过滤、搜索、diff 展示、trace graph、approval 操作、policy debug。

6. **实验体系增强**  
   baseline/ablation 框架已有，仍需要更多真实 agent traces、攻击样本多样化、误报/漏报统计。

## 文档入口

建议阅读顺序：

1. [项目状态与商用化评估](docs/PROJECT_STATUS.zh-CN.md)
2. [真实 Agent 接入指南](docs/REAL_AGENT_INTEGRATION.zh-CN.md)
3. [Gateway 指南](docs/GATEWAY_GUIDE.zh-CN.md)
4. [Agent exec-guard recipes](docs/AGENT_EXEC_GUARD_RECIPES.zh-CN.md)
5. [Sandbox 指南](docs/SANDBOX_GUIDE.zh-CN.md)
6. [Policy Pack 指南](docs/POLICY_PACK_GUIDE.zh-CN.md)
7. [文档目录](docs/README.zh-CN.md)
