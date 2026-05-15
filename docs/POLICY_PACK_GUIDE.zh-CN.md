# Policy Pack / PolicyGraph 规则指南

RepoShield 的策略层由两部分组成：

- `PolicyGraphEngine`：核心安全判断，引擎输出 `allow`、`allow_in_sandbox`、`sandbox_then_approval`、`block`、`quarantine`。
- `PolicyRuntime`：运行时模式包装，用于 enforce、observe_only、warn、disabled 等实验或部署模式。

## 决策语义

```text
allow                  可以在宿主机执行
allow_in_sandbox       只能在沙箱 / overlay / preflight 中执行
sandbox_then_approval  不执行，生成审批请求或等待人工确认
block / quarantine     不执行
```

## Runtime 模式

```text
enforce       保留原始决策
observe_only  effective_decision=allow，但记录 observe_only:would_block
warn          对阻断类动作降级为 allow_in_sandbox，并记录 warning
disabled      全部放行，仅用于对照实验，需要显式 unsafe flag
```

代码入口：

```text
src/reposhield/policy_runtime/policy_pack.py
src/reposhield/policy_runtime/policy_registry.py
policies/policy_registry.yaml
```

## PolicyGraph YAML 规则

核心策略包位于：

```text
src/reposhield/policy_engine/policies/core_coding_agent.yaml
```

典型规则：

```yaml
- rule_id: RS-NET-001
  name: untrusted_source_cannot_authorize_network
  category: egress
  match: {action.semantic_action: send_network_request, source.has_untrusted: true}
  index_hints:
    - {path: action.semantic_action, operator: eq, expected: send_network_request, strategy: exact}
    - {path: source.has_untrusted, operator: eq, expected: true, strategy: exact}
  decision: block
  risk_score: 90
  reason_codes: [untrusted_source_cannot_authorize_network]
  required_controls: [block, no_egress]
```

字段说明：

| 字段 | 作用 |
| --- | --- |
| `rule_id` | 稳定规则 ID，会出现在 trace、Studio 和测试里 |
| `name` | 规则名称 |
| `category` | 规则类别，例如 secret、egress、supply_chain、sandbox |
| `match` | 规则语义条件 |
| `predicates` | 更显式的谓词列表，支持 `eq`、`in`、`exists`、`not_exists`、`contains`、`regex`、`gte`、`lte` |
| `unless` | 排除条件；包含 unless 的规则会作为 residual rule 保守召回 |
| `index_hints` | RuleIndex 检索提示，只影响候选召回和可解释 trace，不改变规则语义 |
| `decision` | 命中后的决策 |
| `risk_score` | 风险分数 |
| `reason_codes` | 可解释原因 |
| `required_controls` | 需要的控制措施，例如 sandbox、approval、no_egress |

## index_hints 使用建议

`index_hints` 用于让 RuleIndex 更快、更清楚地召回候选规则。它应该和 `match` / `predicates` 保持一致，但不替代真正的规则判断。

适合显式索引的事实：

- `action.semantic_action`
- `source.has_untrusted`
- `contract.match`
- `asset.touched_type`
- `package.source`
- `secret.event`
- `sandbox.risk_observed`
- `mcp.capability`
- `memory.authorization`

不建议直接索引的情况：

- 需要正则判断的路径
- `not_exists`
- 复杂 `unless`
- 暂未进入 `FactKeyRegistry` 的任意字段

## 验证策略包

```bash
PYTHONPATH=src python -m reposhield policy-validate \
  --policy-pack src/reposhield/policy_engine/policies/core_coding_agent.yaml
```

相关测试：

```bash
python -m pytest tests/policy_engine/test_policy_pack_yaml.py tests/policy_engine/test_rule_index_v2.py -q
```
