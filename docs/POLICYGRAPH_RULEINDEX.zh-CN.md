# PolicyGraph / RuleIndex 多源证据引擎

这篇文档说明 RepoShield 当前最核心的技术点：如何把 coding agent 的多源证据综合成可解释的安全决策。

## 核心算法：R-MPF

R-MPF 全称为 **Repository-aware Multi-Evidence Policy Fusion**，即“仓库感知的多源证据策略融合算法”。它的目标不是根据单个工具名或黑名单做判断，而是把仓库上下文、用户任务、动作语义、来源可信度、资产风险、供应链信号、沙箱观察和审批状态融合成一个可解释决策。

### 输入

```text
ActionIR + evidence objects
```

其中 evidence objects 可以包括：

- `TaskContract`：用户真正授权的任务边界
- `ContextGraph`：来源可信度和上下文污染关系
- `RepoAssetGraph`：文件路径、资产类型、仓库边界、符号链接风险
- `SecretTaintEvent`：密钥读取、外传、凭据暴露
- `PackageEvent`：依赖来源、生命周期脚本、供应链风险
- MCP / Memory 信号：工具能力、记忆授权状态
- `ExecTrace`：沙箱预检中的进程、网络、文件差异和风险观察
- Approval records：人工审批请求和授权状态

### 步骤

```text
1. Fact Extraction
   从 ActionIR 和 evidence objects 中抽取 PolicyFactSet。

2. Invariants
   先检查不可降级安全门，例如密钥访问、secret 后外传、低可信来源授权高危动作、
   仓库边界逃逸、CI/CD 发布边界和供应链硬阻断。

3. EvidenceIndex / RuleIndex
   通过 FactKeyRegistry 和 FactNormalizer 把事实规范化为索引键，再用 exact、
   presence、range、list、composite、residual 和保守 safe-prune 召回候选规则。

4. PredicateEval
   对候选 PolicyGraph 规则做精确谓词判断，得到哪些 predicate 成立。

5. DecisionLattice
   合并 baseline、invariant hits 和 domain-rule hits，按决策格升级为最严格适用结论。

6. EvidenceGraph
   输出事实、索引召回、谓词、规则、决策格和最终结论之间的因果图。
```

### 输出

```text
PolicyDecision + CausalEvidenceGraph
```

`PolicyDecision` 携带：

- `decision`
- `risk_score`
- `reason_codes`
- `required_controls`
- `matched_rules`
- `evidence_refs`
- `policy_version`
- `rule_trace`

`CausalEvidenceGraph` 携带：

- fact nodes
- retrieval nodes
- predicate nodes
- rule nodes
- lattice nodes
- final decision
- evidence edges

### 性质

| 性质 | 含义 |
| --- | --- |
| Invariant non-downgrade | 不可降级不变量一旦命中，后续普通规则不能把结果降级成直接放行 |
| Indexed retrieval soundness | RuleIndex 可以多召回，但不能漏召回；测试验证 indexed candidates 与 full-scan 命中等价 |
| Decision monotonicity | 更强证据或更高风险规则只会让 DecisionLattice 保持或升级到更严格决策 |

## 为什么需要多源证据

对 coding agent 来说，单独看工具名往往不够。例如同样是 `npm install`，在用户明确要求安装依赖时可能是正常动作；如果它来自低可信 issue 文本，并且指向 GitHub 仓库或压缩包依赖，就可能是供应链攻击。

RepoShield 的判断链路是：

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
| Studio Judgment View | 展示 facts、invariants、RuleIndex、predicates、lattice 和 why_text |

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

## Studio 中怎么看

在 Studio 的“策略判断 / Policy Judgment”视图中，用户应该能直接看到：

1. 哪些 facts 进入判断
2. 哪些 facts 命中 invariant
3. RuleIndex 用哪些证据键召回了哪些规则
4. 哪些 predicate 成立
5. 决策格如何从 allow 升级到 block / sandbox / approval
6. 最终 `why_text` 是什么

这块最适合用来解释项目的核心创新点：RepoShield 不是简单拦截器，而是可观测、可解释、可审计的多源证据融合决策系统。

## 测试保障

当前仓库包含三类 RuleIndex 相关测试：

- 确定性单元测试：验证索引键、组合命中、残余规则和安全剪枝 trace
- 随机等价性测试：验证 indexed candidates 的命中结果等价于 full-scan 规则评估
- 性能基准测试：验证大规则集下候选规则数量显著缩小，并保持稳定响应

运行：

```bash
python -m pytest tests/policy_engine/test_rule_index_v2.py tests/policy_engine/test_rule_index_property.py tests/policy_engine/test_rule_index_perf.py -q
```
