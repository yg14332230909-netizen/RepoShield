# 沙箱与执行证据指南

v0.2 把第一阶段的轻量预演升级为后端抽象。

## Profile 表

```text
read_only          repo read-only, network deny, env redacted
edit_overlay       overlay write, network deny, env redacted
test_sandbox       overlay write, local-only, env redacted
package_preflight  overlay write, registry allowlist, no secrets
ci_dry_run         overlay write, fake services, fake secrets
publish_dry_run    overlay write, fake registry, fake token
mcp_dry_run        no repo write, mcp proxy only, env redacted
```

查看：

```bash
reposhield sandbox-profiles
```

## 后端

```text
SandboxBackend
  ├── DryRunBackend
  ├── SubprocessOverlayBackend
  └── BubblewrapBackend placeholder
```

`SubprocessOverlayBackend` 会在无特权环境中复制仓库、屏蔽 `.env` / `.npmrc` / `.pypirc` / `.ssh` / `.aws`，并只执行明确安全的本地测试命令。高危命令不在主机真实执行，而是生成可审计 `ExecTrace`。

## ExecTrace 字段

```json
{
  "process_tree": ["bash", "npm", "git"],
  "files_read": ["package.json"],
  "files_written": ["package-lock.json", "node_modules/**"],
  "network_attempts": [{"host": "attacker.local", "blocked": true}],
  "env_access": ["RS_CANARY_NPM_TOKEN"],
  "package_scripts": ["postinstall"],
  "diff_summary": ["workflow diff captured in overlay"],
  "risk_observed": ["network_egress_attempt"]
}
```

## 生产替换建议

生产部署时建议替换为：

```text
Linux user/mount/network namespace
seccomp / eBPF syscall tracing
bubblewrap / firejail / containerd
package manager proxy
DNS/HTTP egress monitor
process tree cleanup
```

控制平面只依赖 `SandboxBackend.preflight(...) -> ExecTrace`，所以后端替换不影响策略、审计和 bench。
