"""Generate a portable OpenClaw -> RepoShield setup."""
from __future__ import annotations

import json
from pathlib import Path


def generate_openclaw_quickstart(
    repo: str | Path,
    reposhield_home: str | Path,
    *,
    model: str = "gpt-4.1",
    host: str = "127.0.0.1",
    port: int = 8765,
    upstream_base_url: str = "https://api.openai.com/v1",
    force: bool = False,
) -> dict[str, str]:
    repo_path = Path(repo).resolve()
    home_path = Path(reposhield_home).resolve()
    root = repo_path / ".reposhield" / "openclaw"
    root.mkdir(parents=True, exist_ok=True)

    ps1 = root / "start-reposhield-openclaw.ps1"
    cmd = root / "start-reposhield-openclaw.cmd"
    sh = root / "start-reposhield-openclaw.sh"
    env_example = root / ".env.example"
    provider = root / "openclaw-provider.json"
    readme = root / "README.md"

    _write(
        ps1,
        _powershell_start_script(
            repo_path,
            home_path,
            model=model,
            host=host,
            port=port,
            upstream_base_url=upstream_base_url,
        ),
        force,
    )
    _write(cmd, _cmd_start_script(ps1), force)
    _write(
        sh,
        _posix_start_script(
            repo_path,
            home_path,
            model=model,
            host=host,
            port=port,
            upstream_base_url=upstream_base_url,
        ),
        force,
    )
    _write(env_example, _env_example(repo_path, home_path, model=model, host=host, port=port, upstream_base_url=upstream_base_url), force)
    _write(provider, json.dumps(_provider_config(model=model, host=host, port=port), ensure_ascii=False, indent=2) + "\n", force)
    _write(readme, _quickstart_readme(model=model, host=host, port=port, upstream_base_url=upstream_base_url), force)
    return {
        "start_powershell": str(ps1),
        "start_cmd": str(cmd),
        "start_posix": str(sh),
        "env_example": str(env_example),
        "provider_config": str(provider),
        "readme": str(readme),
        "base_url": f"http://{host}:{port}/v1",
        "api_key": "reposhield-local",
        "model": model,
    }


def _write(path: Path, text: str, force: bool) -> None:
    if path.exists() and not force:
        return
    path.write_text(text, encoding="utf-8")


def _powershell_start_script(repo: Path, reposhield_home: Path, *, model: str, host: str, port: int, upstream_base_url: str) -> str:
    return f"""$ErrorActionPreference = "Stop"

$repo = if ($env:REPOSHIELD_REPO) {{ $env:REPOSHIELD_REPO }} else {{ "{repo}" }}
$reposhieldHome = if ($env:REPOSHIELD_HOME) {{ $env:REPOSHIELD_HOME }} else {{ "{reposhield_home}" }}
$hostName = if ($env:REPOSHIELD_HOST) {{ $env:REPOSHIELD_HOST }} else {{ "{host}" }}
$portNumber = if ($env:REPOSHIELD_PORT) {{ $env:REPOSHIELD_PORT }} else {{ "{port}" }}
$upstreamBaseUrl = if ($env:REPOSHIELD_UPSTREAM_BASE_URL) {{ $env:REPOSHIELD_UPSTREAM_BASE_URL }} else {{ "{upstream_base_url}" }}
$modelName = if ($env:REPOSHIELD_MODEL) {{ $env:REPOSHIELD_MODEL }} else {{ "{model}" }}

if (-not $env:OPENAI_API_KEY) {{
  $env:OPENAI_API_KEY = Read-Host "Paste your upstream OpenAI API key"
}}

if (Test-Path (Join-Path $reposhieldHome "src")) {{
  $env:PYTHONPATH = Join-Path $reposhieldHome "src"
}}

Write-Host "Starting RepoShield for OpenClaw..."
Write-Host "OpenClaw Base URL: http://$hostName`:$portNumber/v1"
Write-Host "OpenClaw API Key:  reposhield-local"
Write-Host "OpenClaw Model:    $modelName"

python -m reposhield gateway-start `
  --repo "$repo" `
  --host "$hostName" `
  --port "$portNumber" `
  --upstream-base-url "$upstreamBaseUrl"
"""


def _cmd_start_script(ps1: Path) -> str:
    return f"""@echo off
powershell -ExecutionPolicy Bypass -File "{ps1}"
"""


def _posix_start_script(repo: Path, reposhield_home: Path, *, model: str, host: str, port: int, upstream_base_url: str) -> str:
    return f"""#!/usr/bin/env sh
set -eu

REPOSHIELD_REPO="${{REPOSHIELD_REPO:-{repo.as_posix()}}}"
REPOSHIELD_HOME="${{REPOSHIELD_HOME:-{reposhield_home.as_posix()}}}"
REPOSHIELD_HOST="${{REPOSHIELD_HOST:-{host}}}"
REPOSHIELD_PORT="${{REPOSHIELD_PORT:-{port}}}"
REPOSHIELD_UPSTREAM_BASE_URL="${{REPOSHIELD_UPSTREAM_BASE_URL:-{upstream_base_url}}}"
REPOSHIELD_MODEL="${{REPOSHIELD_MODEL:-{model}}}"

if [ -z "${{OPENAI_API_KEY:-}}" ]; then
  printf "Paste your upstream OpenAI API key: "
  stty -echo 2>/dev/null || true
  read OPENAI_API_KEY
  stty echo 2>/dev/null || true
  printf "\\n"
  export OPENAI_API_KEY
fi

if [ -d "$REPOSHIELD_HOME/src" ]; then
  export PYTHONPATH="$REPOSHIELD_HOME/src${{PYTHONPATH:+:$PYTHONPATH}}"
fi

printf "Starting RepoShield for OpenClaw...\\n"
printf "OpenClaw Base URL: http://%s:%s/v1\\n" "$REPOSHIELD_HOST" "$REPOSHIELD_PORT"
printf "OpenClaw API Key:  reposhield-local\\n"
printf "OpenClaw Model:    %s\\n" "$REPOSHIELD_MODEL"

python -m reposhield gateway-start \\
  --repo "$REPOSHIELD_REPO" \\
  --host "$REPOSHIELD_HOST" \\
  --port "$REPOSHIELD_PORT" \\
  --upstream-base-url "$REPOSHIELD_UPSTREAM_BASE_URL"
"""


def _env_example(repo: Path, reposhield_home: Path, *, model: str, host: str, port: int, upstream_base_url: str) -> str:
    return f"""# Copy to .env or export these variables before starting the script.
OPENAI_API_KEY=sk-your-upstream-key
REPOSHIELD_REPO={repo}
REPOSHIELD_HOME={reposhield_home}
REPOSHIELD_HOST={host}
REPOSHIELD_PORT={port}
REPOSHIELD_MODEL={model}
REPOSHIELD_UPSTREAM_BASE_URL={upstream_base_url}
"""


def _provider_config(*, model: str, host: str, port: int) -> dict:
    return {
        "models": {
            "mode": "merge",
            "providers": {
                "reposhield": {
                    "baseUrl": f"http://{host}:{port}/v1",
                    "apiKey": "reposhield-local",
                    "api": "openai-completions",
                    "models": [
                        {
                            "id": model,
                            "name": f"{model} via RepoShield",
                            "reasoning": False,
                            "input": ["text"],
                            "contextWindow": 128000,
                            "maxTokens": 32000,
                        }
                    ],
                }
            },
        }
    }


def _quickstart_readme(*, model: str, host: str, port: int, upstream_base_url: str) -> str:
    return f"""# OpenClaw + RepoShield Quickstart

Run one of these scripts from this directory:

```text
Windows PowerShell: ./start-reposhield-openclaw.ps1
Windows CMD:        ./start-reposhield-openclaw.cmd
macOS/Linux:        sh ./start-reposhield-openclaw.sh
```

Paste your real upstream API key when prompted, or set `OPENAI_API_KEY` before
starting the script.

Then add a custom OpenAI-compatible provider in OpenClaw:

```text
Base URL: http://{host}:{port}/v1
API Key:  reposhield-local
Model:    {model}
```

The real upstream is:

```text
{upstream_base_url}
```

OpenClaw should only see the local RepoShield key. Keep the terminal running
while using OpenClaw.

All generated paths can be overridden with environment variables. See
`.env.example`.
"""
