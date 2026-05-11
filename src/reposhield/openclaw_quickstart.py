"""Generate a minimal OpenClaw -> RepoShield local setup."""
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
    _write(provider, json.dumps(_provider_config(model=model, host=host, port=port), ensure_ascii=False, indent=2) + "\n", force)
    _write(readme, _quickstart_readme(model=model, host=host, port=port, upstream_base_url=upstream_base_url), force)
    return {
        "start_powershell": str(ps1),
        "start_cmd": str(cmd),
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

if (-not $env:OPENAI_API_KEY) {{
  $env:OPENAI_API_KEY = Read-Host "Paste your upstream OpenAI API key"
}}

$env:PYTHONPATH = "{reposhield_home / "src"}"

Write-Host "Starting RepoShield for OpenClaw..."
Write-Host "OpenClaw Base URL: http://{host}:{port}/v1"
Write-Host "OpenClaw API Key:  reposhield-local"
Write-Host "OpenClaw Model:    {model}"

python -m reposhield gateway-start `
  --repo "{repo}" `
  --host {host} `
  --port {port} `
  --upstream-base-url {upstream_base_url}
"""


def _cmd_start_script(ps1: Path) -> str:
    return f"""@echo off
powershell -ExecutionPolicy Bypass -File "{ps1}"
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

1. Run `start-reposhield-openclaw.ps1`.
2. Paste your real upstream API key when prompted.
3. In OpenClaw, add a custom OpenAI-compatible provider:

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
"""
