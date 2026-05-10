# RepoShield 项目状态与商用化评估

更新时间：2026-05-10

## 总体判断

RepoShield 当前是 **研究原型加强版 / 工程化 MVP 前期**。

它已经具备完整的安全治理主链路：Gateway、ActionIR、TaskContract、ContextGraph、SecretSentry、PackageGuard、MCP/Memory gate、Sandbox preflight、PolicyEngine、ApprovalCenter、AuditLog、Replay、Dashboard 和 Bench。P0 风险点已基本补完，P1 中大多数影响论文可信度和真实接入闭环的问题也已经有实现与测试。

但它还不是生产级商业安全产品。商用化仍需要生产级隔离、真实供应链情报、真实 agent trace 兼容、策略/审批产品化和更完整的 Studio。

## 成熟度估计

| 使用场景 | 当前成熟度 | 说明 |
| --- | --- | --- |
| 论文 demo / 项目展示 | 85% - 90% | 主链路完整，风险点有测试，适合演示和答辩 |
| 内部实验平台 | 75% - 85% | bench、replay、audit、baseline/ablation 已可用 |
| 小团队本地试用 | 55% - 65% | 可接 Gateway / exec-guard，但需要人工配置和安全边界说明 |
| 商用化安全产品 | 30% - 40% | 缺生产级 sandbox、UI/API、租户隔离、策略管理和真实情报 |

## 当前验证状态

```text
python -m pytest --basetemp=.pytest_tmp -q   -> 77 passed
python -m compileall -q src tests            -> passed
ruff check src tests                         -> passed
```

## P0 状态

P0 可以视为基本完成。

已完成内容：

- 每个 Gateway 请求隔离 `TaskContract` / `ContextGraph` / `SecretSentry`
- Gateway HTTP bearer token 认证
- AuditLog append/read 线程安全
- Gateway-only 模式不释放 `allow_in_sandbox` tool call
- block/sandbox message 做 secret redaction
- `allow_in_sandbox` 语义全路径统一
- GenericCLIAdapter 不再默认执行 pre-governance 外部 command
- compound command lowering 与 fail-closed
- 文件路径 canonicalize、repo escape、symlink escape、hidden secret 检查
- ConfigurablePolicyOverrides 防止高危决策被 unsafe downgrade
- Approval hash 排除 volatile `action_id`

## P1 状态

P1 当前达到 **工程研究版基本完成**。

已经完成或接近完成：

- Gateway 使用 `guard_action_ir()`，不再二次 raw parse
- Gateway confirmation 接入 `ApprovalCenter / ApprovalStore`
- `/v1/responses` 最小 Responses API shape
- streaming tool calls indexed chunk
- upstream SSE 逐行读取、大小和事件数限制
- Gateway 错误响应脱敏
- `SubprocessOverlayBackend` 去掉 `shell=True`
- sandbox profile enforcement matrix
- PolicyDecision 增加 `matched_rules / evidence_refs / policy_version / rule_trace`
- disabled policy mode 要求显式 unsafe flag
- PackageGuard manager parser、registry、lockfile、本地 metadata/provenance oracle
- MCPProxy gate 影响 PolicyEngine 决策
- MemoryStore tainted memory 不能授权高风险动作
- SecretSentry 轻量 file/stdout/stderr taint
- Audit event schema version 和基础校验
- Replay policy evidence 引用校验
- Dashboard evidence chains
- Bench baseline/ablation report shape

仍然属于生产化待补：

- 真实强隔离 sandbox
- 真实 npm/PyPI metadata 和 tarball inspection
- Sigstore / provenance 在线验证
- 完整交互式 Studio
- 多用户/多租户权限模型
- 更大规模真实 agent trace benchmark

## 已实现安全闭环

### Gateway 闭环

```text
request
  -> per-request control plane
  -> build TaskContract
  -> ingest external contexts
  -> upstream model
  -> InstructionIR
  -> ActionIR
  -> guard_action_ir()
  -> PolicyRuntime
  -> transform_response()
  -> audit / approval / response
```

Gateway-only 模式下，只有真正 host-safe 的 `allow` 才可能释放给 agent。`allow_in_sandbox` 会被转换成 sandbox-only assistant message，避免裸 agent 直接在宿主机执行。

### Tool execution 语义

| 决策 | 执行语义 |
| --- | --- |
| `allow` | 可宿主机执行 |
| `allow_in_sandbox` | 只能 sandbox / overlay / preflight |
| `sandbox_then_approval` | 不执行，等待审批 |
| `block` / `quarantine` | 不执行 |

### 审计与 replay

AuditLog 使用 hash-chain，事件有 `schema_version`。Replay 不只检查文件存在和 hash-chain，还会检查 policy decision 是否引用了存在的 action/package/exec trace evidence。

## 商用化差距

### 1. Sandbox

当前：

- dry-run evidence
- overlay test execution
- shell=False for safe tests
- profile enforcement matrix
- 显式 `isolation_level` / `production_ready`

商用需要：

- containerd / Docker / Podman backend
- Linux user/mount/network namespace
- seccomp 或 eBPF tracing
- DNS/HTTP egress monitor
- package lifecycle script capture
- process tree kill 和资源限制

### 2. 供应链情报

当前：

- command parser
- registry 检查
- lockfile evidence
- 本地 `.reposhield/package_metadata.json` oracle

商用需要：

- npm/PyPI live metadata
- package tarball inspection
- Sigstore/provenance verification
- typosquatting detection
- maintainer/reputation signals
- dependency confusion policy

### 3. Agent 兼容

当前：

- OpenAI / Anthropic / Cline / OpenHands / Aider parser mapping
- transcript strict mode
- Gateway-compatible flow

商用需要：

- 真实 Codex/Cline/OpenHands/Aider trace corpus
- schema drift regression tests
- 每个 agent 的安装/配置向导
- 长期兼容性 CI

### 4. 策略和审批

当前：

- PolicyEngine hard-coded rules
- ConfigurablePolicyOverrides
- ApprovalCenter / ApprovalStore

商用需要：

- 稳定策略语言
- 策略签名和版本迁移
- RBAC / admin approval
- Web approval UI
- API key rotation 和 audit export

### 5. Studio / Dashboard

当前：

- 本地 HTML dashboard
- blocked actions
- approval events
- evidence chains

商用需要：

- trace/source/action 过滤
- diff 展示
- approval 操作
- policy rule debug
- 多用户审计检索

## 下一阶段路线图

### R1：可给小团队试用

- 打包 Gateway + exec-guard 安装流程
- 增加配置向导
- 增加真实 agent trace replay
- 增加 dashboard 搜索和过滤
- 完善文档示例和故障排查

### R2：企业 PoC

- container sandbox backend
- package metadata proxy
- approval HTTP API
- 策略文件签名
- CI 集成和结果导出

### R3：商用产品

- 多租户控制台
- RBAC / SSO
- 长期 audit retention
- policy marketplace / templates
- SLA 级服务部署
- agent compatibility test matrix

## 对外表述建议

推荐使用：

> RepoShield is a research-grade pre-execution governance gateway for coding agents, with a working engineering MVP covering gateway interception, tool-call governance, provenance-aware policy decisions, sandbox preflight, approval binding, and tamper-evident audit logs.

不建议现在宣称：

- production-grade sandbox
- enterprise-ready security product
- complete supply-chain intelligence
- complete support for all coding agents

当前最准确的定位是：

```text
论文/演示：成熟
内部实验：可用
小团队试用：可尝试
商业产品：还需工程化
```
