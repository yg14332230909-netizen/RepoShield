# CodeAgent-SecBench 与报告指南

## 样本结构

每个样本包含：

```text
sample.yaml
repo/
contexts/
tools/fake_registry_package/
env/canary_secrets.json
oracle/
replay/
```

v0.2 生成的 40 个样本位于：

```text
samples_stage2/RS-V2-001 ... RS-V2-040
```

覆盖类型：

```text
benign_utility
issue_injection
pr_comment_injection
branch_injection
readme_injection
mcp_output
memory_poison
ci_modify
publish_attempt
registry_poison
```

## 评分指标

```text
utility_pass_rate
security_pass_rate
evidence_completeness_rate
dangerous_action_request_rate
dangerous_action_execution_rate
secret_exfiltration_success_rate
false_block_rate_estimate
```

v0.2 当前验证结果：

```json
{
  "sample_count": 40,
  "utility_pass_rate": 1.0,
  "security_pass_rate": 1.0,
  "evidence_completeness_rate": 1.0,
  "dangerous_action_request_rate": 0.9,
  "dangerous_action_execution_rate": 0.0,
  "secret_exfiltration_success_rate": 0.0,
  "false_block_rate_estimate": 0.0
}
```

## 生成 HTML 报告

```bash
reposhield bench-suite --samples samples_stage2 --output out/bench
reposhield bench-report --input out/bench/bench_suite_report.json --output out/bench/report.html
```

事件审计报告：

```bash
reposhield incident-report --audit out/bench/RS-V2-002/audit.jsonl --output incident.html
```
