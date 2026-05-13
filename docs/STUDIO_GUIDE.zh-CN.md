# RepoShield Studio 指南

Studio 有两种形态：

- `reposhield studio`：生成静态 HTML 报告，适合离线归档和论文材料打包。
- `reposhield studio-server`：启动交互式 Studio Pro，本地实时观察真实 agent/Gateway 请求。

## Studio Pro 实时模式

启动本地前端：

```bash
PYTHONPATH=src python -m reposhield studio-server \
  --audit .reposhield/gateway_audit.jsonl \
  --approvals .reposhield/gateway_approvals.jsonl \
  --bench-report reports/gateway_bench/gateway_bench_report.json \
  --host 127.0.0.1 \
  --port 8780 \
  --demo-mode
```

打开：

```text
http://127.0.0.1:8780
```

Studio Pro 会订阅全局 SSE：

```text
/api/events/stream
```

因此真实 OpenClaw、OpenHands、Aider 或其他 OpenAI-compatible agent 经过 RepoShield Gateway 产生新事件时，前端会自动更新运行列表、时间线和当前运行视图。页面顶部会显示“自动观测中 / 同步中 / 同步异常”和最后同步时间；同时保留短间隔轮询作为兜底。

## 页面分区

```text
本次运行：当前请求的时间线、动作、决策流
攻击演示：内置 normal / attack 场景
安全决策追踪图：source -> instruction -> action -> decision 的证据路径
拦截原因：策略命中、风险原因、最终决策
人工审批：需要人工确认的高风险动作
沙箱预检：进程、网络、文件差异和脱敏证据
安全成绩单：Gateway bench 指标和失败样本
动作详情：点击动作后查看 ActionIR、策略解释和原始证据
```

## 清空记录

在 `--demo-mode` 下，侧边栏提供“清空演示记录”。它只会清空本地 audit / approvals 日志，不会删除项目代码。清空前页面会询问是否备份：

- 选择备份：写入 `.reposhield/studio_backups/<timestamp>/`
- 选择不备份：直接清空，不创建备份目录

## 静态报告

生成静态 Studio Lite：

```bash
PYTHONPATH=src python -m reposhield studio \
  --audit reports/gateway_demo_run/gateway_audit.jsonl \
  --bench-report reports/stage3_gateway_bench/gateway_bench_report.json \
  --output reports/stage3_studio.html \
  --title "RepoShield v0.3 Studio"
```

静态报告适合离线展示；如果要观察真实 agent 运行过程，优先使用 `studio-server`。
