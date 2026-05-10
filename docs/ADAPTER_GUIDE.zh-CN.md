# Agent Adapter 开发指南

RepoShield 的 adapter 不负责生成代码，只负责把外部 agent 的计划和工具调用转成 RepoShield 可理解的动作，并严格执行控制平面的决策。

## 最小 adapter 责任

```python
from reposhield.control_plane import RepoShieldControlPlane

cp = RepoShieldControlPlane(repo)
cp.build_contract(user_task)
action, decision = cp.guard_action(raw_action, source_ids=[...], tool='Bash')

if decision.decision == 'allow':
    execute_or_apply_action()
elif decision.decision == 'allow_in_sandbox':
    run_only_in_sandbox_overlay_or_preflight()
elif decision.decision == 'sandbox_then_approval':
    request_human_approval()
else:
    block_action()
```

## 已内置 adapter

```text
src/reposhield/adapters/base.py
src/reposhield/adapters/protocol.py
src/reposhield/adapters/generic_cli.py
src/reposhield/adapters/aider.py
```

`generic_cli` 支持 transcript 行：

```text
RS_ACTION: npm test
RUN: pytest
EDIT: src/login.js
READ: README.md
```

`aider` adapter 是第一个真实 agent 形态适配器：它可解析外部 CLI 输出，也可在没有 aider 的环境中运行 deterministic demo plan。

## source_ids 很重要

如果动作受 issue、PR、branch、README、MCP output、memory 影响，adapter 必须把对应 `source_id` 带入 `guard_action`。否则策略引擎无法判断“不可信上下文影响了高危动作”。

示例：

```python
src = cp.ingest_source('github_issue_body', issue_body, retrieval_path='issue#17')
cp.guard_action('npm install github:attacker/helper-tool', source_ids=[src.source_id])
```

## 审批一致性

adapter 不应把 approval 当作通用许可。RepoShield 的 approval 绑定：

```text
plan_hash
action_hash
constraints
expiry
task_id
```

执行前 action 变化、plan 变化、过期、网络/lifecycle 约束不匹配，均应阻断。
