"""Generate RepoShield agent integration scaffolding."""
from __future__ import annotations

import json
from pathlib import Path

SHIM_NAMES = ["npm", "git", "curl", "python"]


def init_agent(repo: str | Path, reposhield_home: str | Path, agent: str = "generic", task: str = "general coding task", force: bool = False) -> dict:
    repo_path = Path(repo).resolve()
    root = repo_path / ".reposhield"
    shims = root / "shims"
    root.mkdir(parents=True, exist_ok=True)
    shims.mkdir(parents=True, exist_ok=True)

    config = {
        "agent": agent,
        "repo": str(repo_path),
        "reposhield_home": str(Path(reposhield_home).resolve()),
        "task": task,
        "gateway_base_url": "http://127.0.0.1:8765/v1",
        "api_key": "reposhield-local",
    }
    _write(root / "config.json", json.dumps(config, ensure_ascii=False, indent=2) + "\n", force)
    _write(root / "agent-instructions.md", _instructions(config), force)
    for name in SHIM_NAMES:
        _write(shims / name, _posix_shim(name), force)
        _write(shims / f"{name}.ps1", _powershell_shim(name), force)
    return {"config": str(root / "config.json"), "instructions": str(root / "agent-instructions.md"), "shims": str(shims), "agent": agent}


def _write(path: Path, text: str, force: bool) -> None:
    if path.exists() and not force:
        return
    path.write_text(text, encoding="utf-8")


def _instructions(config: dict) -> str:
    return f"""# RepoShield agent instructions

Use RepoShield for model and shell execution.

Model API:

```text
base_url = {config['gateway_base_url']}
api_key  = {config['api_key']}
```

Shell commands:

```bash
PYTHONPATH={config['reposhield_home']}/src python -m reposhield exec-guard --repo {config['repo']} --task "{config['task']}" -- <command>
```

If PATH shims are enabled, put `{config['repo']}/.reposhield/shims` first in PATH.
"""


def _posix_shim(name: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
REAL_CMD="$(command -v {name}.real || true)"
if [ -z "$REAL_CMD" ]; then
  REAL_CMD="/usr/bin/{name}"
fi
PYTHONPATH="${{REPOSHIELD_HOME}}/src" python -m reposhield exec-guard \\
  --repo "${{REPOSHIELD_REPO:-$PWD}}" \\
  --task "${{REPOSHIELD_TASK:-general coding task}}" \\
  -- "$REAL_CMD" "$@"
"""


def _powershell_shim(name: str) -> str:
    return f"""$repo = if ($env:REPOSHIELD_REPO) {{ $env:REPOSHIELD_REPO }} else {{ (Get-Location).Path }}
$task = if ($env:REPOSHIELD_TASK) {{ $env:REPOSHIELD_TASK }} else {{ "general coding task" }}
$rs = if ($env:REPOSHIELD_HOME) {{ $env:REPOSHIELD_HOME }} else {{ (Resolve-Path ".").Path }}
$env:PYTHONPATH = Join-Path $rs "src"
python -m reposhield exec-guard --repo $repo --task $task -- {name} @args
exit $LASTEXITCODE
"""

