# RepoShield Studio 指南

Studio 是 v0.3 的轻量 HTML 控制台，用于展示 Gateway trace、Incident graph、Policy hits 和 Bench metrics。

生成命令：

```bash
PYTHONPATH=src python -m reposhield studio \
  --audit reports/gateway_demo_run/gateway_audit.jsonl \
  --bench-report reports/stage3_gateway_bench/gateway_bench_report.json \
  --output reports/stage3_studio.html \
  --title 'RepoShield v0.3 Studio'
```

页面包含：

```text
Trace：gateway_pre_call → instruction_ir → action_parsed → policy_decision → gateway_response
Incident：source / instruction / action / decision 节点
Policy：核心策略与 runtime mode 命中记录
Bench：Gateway Bench 指标
```

当前 Studio 是静态 HTML，便于离线展示和打包。后续可以把 `src/reposhield/studio/app.py` 包装成在线 dashboard。
