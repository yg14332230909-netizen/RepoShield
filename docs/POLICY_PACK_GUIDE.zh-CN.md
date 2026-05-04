# Policy Pack Runtime 指南

v0.3 在原有 `PolicyEngine` 外增加 `PolicyRuntime`，用于控制策略包运行模式。核心策略仍输出五类决策：

```text
allow
allow_in_sandbox
sandbox_then_approval
block
quarantine
```

PolicyRuntime 再把核心决策转换成运行时效果：

```text
enforce       保留原始决策
observe_only  effective_decision=allow，但记录 observe_only:would_block
warn          对阻断类动作降级成 allow_in_sandbox 并记录 warning
disabled      全部放行，仅用于对照实验
```

代码入口：

```text
src/reposhield/policy_runtime/policy_pack.py
src/reposhield/policy_runtime/policy_registry.py
policies/policy_registry.yaml
```

示例：

```python
from reposhield.policy_runtime import PolicyRuntime
runtime = PolicyRuntime(mode="observe_only")
result = runtime.apply(core_decision)
```

建议角色：

```text
local_dev_strict     本地开发严格模式
benchmark_observe    评测对照模式，只记录 would_block
release_guard        发布链路强保护模式
```
