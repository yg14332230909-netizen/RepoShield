# PolicyGraph / RuleIndex 多源证据引擎

这篇文档说明 RepoShield 当前最核心的技术点：如何把 coding agent 的多源证据综合成可解释的安全决策。

## 为什么需要多源证据

对 coding agent 来说，单独看工具名往往不够。例如同样是 `npm install`，在用户明确要求安装依赖时可能是正常动作；如果它来自低可信 issue 文本，并且指向 GitHub 私有仓库或压缩包依赖，就可能是供应链攻击。

RepoShield 的判断方式是：

```text
原始事件
  -> 结构化证据
  -> 标准事实
  -> RuleIndex 候选规则检索
  -> PolicyGraph 谓词判断
  -> 决策格合并
  -> allow / sandbox / approval / block
```

## 主要模块

| 模块 | 作用 |
| --- | --- |
| `FactKeyRegistry` | 声明可以进入索引和 UI 的事实键，包括值类型、索引策略、安全角色和中文说明 |
| `FactNormalizer` | 将布尔、枚举、列表、数值区间统一成稳定 token |
| `RuleCompiler V2` | 编译 DSL 规则，生成 `IndexHint` 和 `RuleSignature` |
| `EvidenceIndex` | 维护 exact、presence、range、list、composite、residual 等索引结构 |
| `RuleIndex` | 根据本次事实召回候选规则，并输出 `retrieval_trace` |
| `PolicyGraph` | 执行谓词判断、不变量判断和决策格合并 |
| Studio RuleIndex 面板 | 解释索引事实、组合命中、残余规则、剪枝原因、候选集和压缩率 |

## FactKeyRegistry

当前注册的核心事实包括：

- `action.semantic_action`：动作类型，例如跑测试、联网、读密钥、安装依赖
- `action.high_risk`：是否属于高危动作
- `source.has_untrusted`：是否受到低可信来源影响
- `asset.touched_type`：触碰资产类型，例如源码、密钥文件、CI 工作流
- `contract.match`：动作是否符合任务边界
- `package.source`：依赖来自 registry、git_url 还是 tarball_url
- `secret.event`：密钥相关事件
- `sandbox.risk_observed`：沙箱预检观察到的风险
- `mcp.capability`：MCP 工具暴露的能力
- `memory.authorization`：记忆授权状态

这些事实会被规范化成类似下面的索引键：

```text
source.has_untrusted=true
asset.touched_type=secret_file
contract.match=violation
package.source=git_url
```

## RuleIndex 如何缩小候选规则

RuleIndex 的目标不是代替策略判断，而是在保证不漏召回的前提下减少需要评估的规则数量。

它会记录：

- `indexed_fact_keys`：本次动作产生了哪些可索引事实
- `postings`：单个事实命中了哪些规则
- `composite_hits`：多个事实组合命中了哪些规则
- `residual_rules`：包含正则、`not_exists`、`unless` 等复杂逻辑，需要兜底保留
- `candidate_rule_ids`：最终进入 PolicyGraph 精确判断的候选规则
- `candidate_reduction_ratio`：候选规则占全部规则的比例
- `pruned`：启用安全剪枝时，被证明不可能匹配而移除的规则

## 残余规则兜底

正则、缺失判断、unless 以及某些复杂分组条件不适合直接用索引证明，因此会进入 residual 集合。这样做牺牲一点性能，但能保证策略召回安全。

换句话说：

```text
索引可以多召回，不能少召回。
```

## 安全剪枝

安全剪枝只在可以证明“不可能匹配”时移除规则。例如：

```text
事实：action.semantic_action=run_tests
规则要求：action.semantic_action=delete_repo
```

对于这种单值、单调安全的事实，如果实际值和规则必需值没有交集，就可以剪掉。默认主链路仍采用保守模式，优先保证不漏召回；测试中会验证开启剪枝后的证明路径。

## YAML 规则中的 index_hints

规则可以显式声明索引提示：

```yaml
- rule_id: RS-NET-001
  name: untrusted_source_cannot_authorize_network
  match: {action.semantic_action: send_network_request, source.has_untrusted: true}
  index_hints:
    - {path: action.semantic_action, operator: eq, expected: send_network_request, strategy: exact}
    - {path: source.has_untrusted, operator: eq, expected: true, strategy: exact}
  decision: block
```

`match` 决定规则语义，`index_hints` 只决定如何更快、更可解释地召回候选规则。

## Studio 中怎么看

在 Studio 的“策略判断 / Policy Judgment”视图中，RuleIndex 面板会显示：

1. 全部规则数量
2. 事实索引命中数量
3. 残余规则兜底数量
4. 安全剪枝移除数量
5. 最终候选规则
6. 实际命中条件
7. 候选集压缩效果

这块最适合用来解释项目的核心创新点：RepoShield 不是简单拦截，而是在展示“哪些证据进入判断、哪些规则被召回、为什么最后形成这个决策”。

## 测试保障

当前仓库包含三类 RuleIndex 相关测试：

- 确定性单元测试：验证索引键、组合命中、残余规则和安全剪枝 trace
- 随机等价性测试：验证 indexed candidates 的命中结果等价于 full-scan 规则评估
- 性能基准测试：验证大规则集下候选规则数量显著缩小，并保持稳定响应

运行：

```bash
python -m pytest tests/policy_engine/test_rule_index_v2.py tests/policy_engine/test_rule_index_property.py tests/policy_engine/test_rule_index_perf.py -q
```
