# RepoShield Studio 指南

Studio 有两种形态：

- `reposhield studio`：生成静态 HTML 报告，适合离线归档、论文材料和演示包。
- `reposhield studio-server`：启动交互式 Studio Pro，本地实时观察真实 agent / Gateway 请求。

## 启动 Studio Pro

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

真实 OpenClaw、OpenHands、Aider 或其他 OpenAI-compatible agent 经过 RepoShield Gateway 产生新事件时，前端会自动更新运行列表、时间线和当前运行视图。页面顶部会显示同步状态，同时保留短间隔轮询作为兜底。

## 页面分区

| 分区 | 作用 |
| --- | --- |
| 本次运行 | 当前请求的运行列表、时间线、动作和决策流 |
| 攻击演示 | 内置 normal / attack 场景，适合快速产生可展示数据 |
| 证据图谱 | 展示 source -> instruction -> action -> decision -> evidence 的路径 |
| 策略判断 | 展示 Evidence -> Facts -> RuleIndex -> Rules -> Lattice -> Decision 的完整链路 |
| 策略调试 | 运行级 Policy Debugger，用于定位误报、漏报和规则缺口 |
| 审批中心 | 对需要人工确认的动作进行 grant / deny |
| 沙箱证据 | 展示进程、网络、文件差异和脱敏执行证据 |
| 评测报告 | 展示 Gateway bench 指标和失败样本 |
| 动作详情 | 点击动作后查看 ActionIR、策略解释、证据引用和原始 trace |

## 策略判断里看什么

这一页是展示项目核心创新点的重点：

```text
Evidence -> Facts -> RuleIndex -> PolicyGraph -> Decision
```

主要组件：

- 多源证据入口：说明这次动作用了哪些来源、动作、资产、任务边界、安全事件和执行证据。
- Fact Matrix：把内部事实键翻译成人能理解的安全事实。
- RuleIndex 面板：解释哪些事实命中了规则、哪些组合证据命中、哪些规则被残余兜底、最终候选集有多大。
- Predicate Matrix：逐条展示规则条件的期望值、实际证据和是否命中。
- Decision Lattice：解释多个规则和不变量如何合并成最终决策。
- Why Decision：用自然语言说明为什么放行、沙箱、审批或阻断。

## 清空记录

在 `--demo-mode` 下，侧边栏提供“清空演示记录”。它只会清空本地 audit / approvals 日志，不会删除项目代码。

清空前页面会询问是否备份：

- 选择备份：写入 `.reposhield/studio_backups/<timestamp>/`
- 选择不备份：直接清空，不创建备份目录

## 静态 Studio Lite

```bash
PYTHONPATH=src python -m reposhield studio \
  --audit reports/gateway_demo_run/gateway_audit.jsonl \
  --bench-report reports/stage3_gateway_bench/gateway_bench_report.json \
  --output reports/stage3_studio.html \
  --title "RepoShield v0.3 Studio"
```

静态报告适合离线展示；如果要观察真实 agent 运行过程，优先使用 `studio-server`。
