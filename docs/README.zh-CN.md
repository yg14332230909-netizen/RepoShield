# RepoShield 文档地图

RepoShield 是一个面向 coding agent 的执行前治理网关。它不替代 agent，而是插在真实 agent 和模型 API / 工具执行链路之间：

```text
真实 agent -> RepoShield Gateway / exec-guard / file-guard -> 策略判断 -> 放行、沙箱、审批或阻断
```

## 新人先看

1. [项目首页](../README.md)  
   用最短路径理解 RepoShield 是什么、能防什么、怎么接入。
2. [真实 Agent 接入指南](REAL_AGENT_INTEGRATION.zh-CN.md)  
   解释 Gateway、exec-guard、tool call 治理和当前边界。
3. [Cline / Codex / OpenHands 配置示例](AGENT_EXEC_GUARD_RECIPES.zh-CN.md)  
   给真实 agent 配 `base_url`，并把 shell 工具指向 RepoShield。

## 核心能力

- [Gateway 指南](GATEWAY_GUIDE.zh-CN.md)：OpenAI-compatible 网关、真实 upstream、streaming 响应。
- [Adapter 指南](ADAPTER_GUIDE.zh-CN.md)：如何给不同 agent 写工具适配层。
- [Tool Parser Plugin 指南](TOOL_PARSER_PLUGIN_GUIDE.zh-CN.md)：如何解析 OpenAI、Claude、Cline、Aider、OpenHands 等工具格式。
- [Sandbox 指南](SANDBOX_GUIDE.zh-CN.md)：本地预演和沙箱边界。
- [Policy Pack 指南](POLICY_PACK_GUIDE.zh-CN.md)：策略包和规则组织方式。

## 评测和报告

- [测试样本说明](TEST_CASES.zh-CN.md)
- [Gateway Bench 指南](BENCH_GATEWAY_GUIDE.zh-CN.md)
- [Bench Report 指南](BENCH_REPORT_GUIDE.zh-CN.md)
- [Studio 指南](STUDIO_GUIDE.zh-CN.md)

## 历史阶段文档

这些文档保留用于理解项目演进，不建议作为新手入口：

- [第二阶段使用说明](SECOND_STAGE_USAGE.zh-CN.md)
- [第三阶段使用说明](THIRD_STAGE_USAGE.zh-CN.md)

## 当前完成度

已经可用：

- 真实 OpenAI-compatible upstream 转发
- agent 侧 `stream=true` 的 SSE 响应
- upstream streaming 聚合后再治理 tool calls
- `exec-guard` shell 命令治理
- `file-guard` 文件读写删改治理
- `init-agent` 一键生成 repo-local 配置、说明和 PATH shims
- `approvals` CLI 审批 list / approve / deny 闭环
- JSON/YAML policy override
- 本地 HTML dashboard
- CI workflow 和 ruff 配置

仍需继续产品化：

- token-by-token 的真流式透传治理
- 更强的跨平台 shell / script parser
- 更隔离的沙箱运行时
- 针对具体 agent 的更完整 adapter
- Web 审批 UI、团队策略、权限记忆和策略中心
