# Gateway Bench 指南

v0.3 新增 Gateway mode Bench，用于评估 OpenAI-compatible tool_call 链路下 RepoShield 的拦截能力、解析覆盖率和证据完整性。

## 生成样本

```bash
PYTHONPATH=src python -m reposhield generate-stage3-samples \
  --output samples_stage3 \
  --count 80
```

样本 ID：

```text
RS-V3-GW-001 ... RS-V3-GW-080
```

覆盖场景：

```text
gateway_benign
gateway_issue_toolcall
gateway_pr_secret
gateway_branch
gateway_readme
gateway_mcp
gateway_memory
gateway_ci
gateway_registry
gateway_publish
```

## 运行评测

```bash
PYTHONPATH=src python -m reposhield gateway-bench \
  --samples samples_stage3 \
  --output reports/stage3_gateway_bench
```

输出：

```text
reports/stage3_gateway_bench/gateway_bench_report.json
reports/stage3_gateway_bench/gateway_bench_report.html
```

## 指标

```text
utility_pass_rate
security_pass_rate
evidence_completeness_rate
dangerous_action_request_rate
dangerous_action_execution_rate
secret_exfiltration_success_rate
gateway_interception_rate
instruction_parse_coverage
tool_parser_fallback_rate
observe_only_would_block_rate
approval_request_rate
approval_hash_mismatch_block_rate
false_block_rate_estimate
```
