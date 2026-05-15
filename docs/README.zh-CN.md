# RepoShield 文档目录

RepoShield 是 coding agent 的执行前安全治理网关。它可以作为 OpenAI-compatible Gateway，也可以通过 `exec-guard`、file guard、PATH shim 等方式接入真实 agent 的工具执行路径。

## 推荐阅读顺序

1. [顶层中文 README](../README.zh-CN.md)  
   项目定位、核心能力、快速开始和整体架构。
2. [PolicyGraph / RuleIndex 多源证据引擎](POLICYGRAPH_RULEINDEX.zh-CN.md)  
   当前项目最大的技术创新点：Evidence -> Facts -> RuleIndex -> PolicyGraph -> Decision。
3. [Studio 指南](STUDIO_GUIDE.zh-CN.md)  
   如何启动实时前端，以及如何在界面中解释证据图谱、策略判断、审批和沙箱证据。
4. [真实 Agent 接入指南](REAL_AGENT_INTEGRATION.zh-CN.md)  
   Gateway、exec-guard、tool call 解析和 OpenClaw / OpenHands / Aider 接入方式。
5. [Gateway 指南](GATEWAY_GUIDE.zh-CN.md)  
   OpenAI-compatible Gateway、认证、上游转发、streaming 和 release mode。
6. [Policy Pack / PolicyGraph 规则指南](POLICY_PACK_GUIDE.zh-CN.md)  
   决策语义、runtime 模式、YAML 规则、`index_hints` 和验证方式。
7. [项目状态与商用化评估](PROJECT_STATUS.zh-CN.md)  
   当前成熟度、已完成能力、剩余差距和路线图。

## 接入与扩展

- [Adapter 指南](ADAPTER_GUIDE.zh-CN.md)  
  如何把外部 coding agent 的 plan、transcript、tool call 转换为 RepoShield 可治理的 action。
- [Tool Parser Plugin 指南](TOOL_PARSER_PLUGIN_GUIDE.zh-CN.md)  
  如何为 OpenAI、Anthropic、Cline、OpenClaw、OpenHands、Aider 等 tool schema 增加 parser mapping。
- [Agent exec-guard recipes](AGENT_EXEC_GUARD_RECIPES.zh-CN.md)  
  常见 agent 的 shell 工具接入方式。
- [使用指南](USAGE.zh-CN.md)  
  常见 CLI 命令和本地运行方式。

## Bench / Replay / Studio

- [Gateway Bench 指南](BENCH_GATEWAY_GUIDE.zh-CN.md)
- [Bench Report 指南](BENCH_REPORT_GUIDE.zh-CN.md)
- [Studio 指南](STUDIO_GUIDE.zh-CN.md)
- [测试用例说明](TEST_CASES.zh-CN.md)

## 阶段说明

- [第二阶段使用说明](SECOND_STAGE_USAGE.zh-CN.md)
- [第三阶段使用说明](THIRD_STAGE_USAGE.zh-CN.md)

## 当前能力摘要

RepoShield 当前已经具备：

- OpenAI-compatible Gateway
- per-request control plane isolation
- Authorization
- `allow_in_sandbox` sandbox-only 语义
- ToolParserRegistry
- InstructionIR / ActionIR
- TaskContract
- Context provenance
- SecretSentry
- PackageGuard
- MCPProxy / MemoryStore gates
- Sandbox preflight
- PolicyGraph / RuleIndex 多源证据综合判断
- PolicyRuntime
- ApprovalCenter / ApprovalStore
- AuditLog hash-chain
- Replay evidence validation
- Studio Pro 实时前端
- Stage2 / Stage3 bench 和 baseline / ablation 报告

当前仍未完成商用化的部分：

- 生产级强隔离 sandbox
- 真实供应链 metadata / tarball / Sigstore 情报
- 更大规模真实 agent traces 和兼容性测试
- 团队权限、长期存储、审计查询和多租户管理
- 大规模误报、漏报统计
