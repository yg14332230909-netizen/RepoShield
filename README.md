# RepoShield
A zero-trust execution firewall for coding agents.

RepoShield 是一个面向代码智能体的上下文溯源、意图绑定与零信任执行防火墙。

## 项目背景

Claude Code、Codex、Cline 等代码智能体已经能够读取仓库、修改文件、执行命令、调用工具，甚至接入 CI/CD 和发布链路。GitHub issue、PR 评论、README、分支名、MCP 工具输出和依赖包脚本等不可信上下文，可能诱导代码智能体执行危险动作，例如读取密钥、安装恶意依赖、修改 CI 配置或外发敏感信息。

RepoShield 的目标是在代码智能体真正执行动作之前，对上下文来源、任务意图、动作语义、执行环境和外发行为进行统一约束与审计。

## 核心能力

- 上下文来源标记
- 任务合同生成
- 动作语义解析
- 策略决策引擎
- 沙箱预演
- 敏感信息外发检测
- 攻击链审计回放
- CodeAgent-SecBench 评测集

## 当前阶段

项目处于 MVP 阶段，当前目标是跑通第一条完整攻击链：

恶意 issue / README  
→ 诱导 agent 生成危险动作  
→ RepoShield 识别动作风险  
→ 策略引擎阻断  
→ 输出审计报告  

## 开发规范

所有成员必须遵守：

1. 不直接修改 main 分支。
2. 每个功能单独创建 feature 分支。
3. 每次提交必须写清楚 commit message。
4. 合并代码前必须提交 Pull Request。
5. 不允许上传真实 token、密钥、.env、SSH key 或 API key。