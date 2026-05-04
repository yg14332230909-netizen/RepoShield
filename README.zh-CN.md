# RepoShield / PepoShield v0.3

RepoShield 是面向代码智能体的上下文溯源、意图绑定与零信任执行防火墙。v0.3 在 v0.2 的 adapter、沙箱、MCP、Memory、Approval、Bench 和审计能力上，继续加入 **OpenAI-compatible Governance Gateway**、**InstructionIR**、**tool parser plugin registry**、**policy plugin runtime**、**two-layer taint registry**、**RepoShield Studio** 和 **80 个 Gateway Bench 样本**。

> 命令入口同时保留 `reposhield` 和 `peposhield`。

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

核心新增目录：

```text
src/reposhield/gateway/          OpenAI-compatible Gateway
src/reposhield/instruction_ir/   InstructionIR schema、builder、lowering
src/reposhield/plugins/          tool parser plugin registry
src/reposhield/policy_runtime/   enforce / observe_only / warn / disabled
src/reposhield/registry/         source/user two-layer registry + taint store
src/reposhield/studio/           HTML Studio dashboard
src/reposhield/gateway_bench.py  80 个 Gateway Bench 样本生成与评分
samples_stage3/                  v0.3 Gateway Bench 样本
reports/                         demo、bench、studio、incident 报告
```

## 快速开始

```bash
cd reposhield_plugin_v0.3
python -m pip install -e '.[test]'
python -m compileall -q src
pytest -q
```

运行 v0.3 Gateway demo：

```bash
PYTHONPATH=src python -m reposhield gateway-demo --workdir reports/gateway_demo_run
```

启动本地 OpenAI-compatible Gateway：

```bash
PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./demo_repo \
  --host 127.0.0.1 \
  --port 8765
```

支持的本地路由：

```text
POST http://127.0.0.1:8765/v1/chat/completions
POST http://127.0.0.1:8765/v1/responses
```

真实 agent 只要能配置 OpenAI-compatible endpoint，就可以指向：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = reposhield/local-heuristic 或实际上游 model 名
```

生成并运行第三阶段 Gateway Bench：

```bash
PYTHONPATH=src python -m reposhield generate-stage3-samples \
  --output samples_stage3 \
  --count 80

PYTHONPATH=src python -m reposhield gateway-bench \
  --samples samples_stage3 \
  --output reports/stage3_gateway_bench
```

生成 Studio：

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

详见：`TEST_RUN_RESULT.txt`。

## 文档入口

```text
docs/THIRD_STAGE_USAGE.zh-CN.md
docs/GATEWAY_GUIDE.zh-CN.md
docs/POLICY_PACK_GUIDE.zh-CN.md
docs/TOOL_PARSER_PLUGIN_GUIDE.zh-CN.md
docs/STUDIO_GUIDE.zh-CN.md
docs/BENCH_GATEWAY_GUIDE.zh-CN.md
```

## 说明

v0.3 的 Gateway 和沙箱后端仍以本地演示、测试和可回放评测为目标。`gateway-start` 使用标准库 HTTP server；生产环境可以把 `RepoShieldGateway` 包到 FastAPI、LiteLLM proxy、企业网关或真实 Linux namespace/eBPF/seccomp 后端中。控制平面、ActionIR、InstructionIR、policy runtime、审计、Studio 和 Bench 接口已经为这类替换预留。
