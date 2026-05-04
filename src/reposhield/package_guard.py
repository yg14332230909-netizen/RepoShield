"""Package-manager and software-supply-chain guard."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import ActionIR, PackageEvent, new_id


class PackageGuard:
    def __init__(self, repo_root: str | Path, allowed_registries: list[str] | None = None):
        self.repo_root = Path(repo_root)
        self.allowed_registries = allowed_registries or ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "fake-registry.local"]

    def analyze(self, action: ActionIR) -> PackageEvent | None:
        if not action.semantic_action.startswith("install_") and action.semantic_action != "publish_artifact" and action.semantic_action != "modify_registry_config":
            return None
        if action.semantic_action == "publish_artifact":
            return PackageEvent(
                package_event_id=new_id("pkg"),
                action_id=action.action_id,
                event_type="publish_attempt",
                package=None,
                source="registry_publish",
                lifecycle_scripts=[],
                registry=self._registry_from_config() or "unknown",
                risk="critical",
                decision="double_approval_required",
                reason_codes=["publish_artifact", "supply_chain_boundary"],
            )
        if action.semantic_action == "modify_registry_config":
            return PackageEvent(
                package_event_id=new_id("pkg"),
                action_id=action.action_id,
                event_type="registry_config_change",
                package=None,
                source="registry_config",
                lifecycle_scripts=[],
                registry="changed_registry",
                risk="critical",
                decision="block_or_approval",
                reason_codes=["modify_registry_config"],
            )

        targets = action.metadata.get("package_args", []) if action.metadata else []
        package = targets[0] if targets else self._extract_package(action.raw_action)
        source = self._source_for_package(package or action.raw_action)
        lifecycle_scripts = self._lifecycle_scripts_for(package)
        registry = self._registry_from_command(action.raw_action) or self._registry_from_config() or "official_or_default"
        reason_codes: list[str] = []
        risk = "high"
        decision = "approval_required"

        if source in {"git_url", "tarball_url"}:
            reason_codes.append(f"dependency_source_{source}")
            risk = "critical" if package and re.search(r"attacker|unknown|helper", package, re.I) else "high"
            decision = "block_or_high_approval"
        if lifecycle_scripts:
            reason_codes.append("lifecycle_script_possible")
            risk = "critical" if risk == "high" else risk
        if registry not in {"official_or_default", *self.allowed_registries}:
            reason_codes.append("registry_unknown_or_changed")
            risk = "critical"
        if not reason_codes:
            reason_codes.append("install_registry_dependency")

        return PackageEvent(
            package_event_id=new_id("pkg"),
            action_id=action.action_id,
            event_type="dependency_install",
            package=package,
            source=source,
            lifecycle_scripts=lifecycle_scripts,
            registry=registry,
            risk=risk,  # type: ignore[arg-type]
            decision=decision,
            reason_codes=reason_codes,
        )

    def _extract_package(self, raw: str) -> str | None:
        m = re.search(r"\b(?:npm|pnpm|yarn|pip|pip3|poetry)\s+(?:install|i|add)\s+([^\s]+)", raw, re.I)
        return m.group(1) if m else None

    def _source_for_package(self, package: str | None) -> str:
        if not package:
            return "unknown"
        p = package.lower()
        if p.startswith(("git+", "git@")) or p.startswith("github:"):
            return "git_url"
        if p.startswith(("http://", "https://")) or p.endswith(".tgz") or p.endswith(".tar.gz"):
            return "tarball_url"
        if p.startswith("-r"):
            return "requirements_file"
        return "registry"

    def _registry_from_command(self, raw: str) -> str | None:
        m = re.search(r"--registry[=\s]+([^\s]+)", raw, re.I)
        if not m:
            m = re.search(r"--index-url[=\s]+([^\s]+)", raw, re.I)
        if not m:
            return None
        return re.sub(r"^https?://", "", m.group(1)).split("/")[0]

    def _registry_from_config(self) -> str | None:
        for config in [self.repo_root / ".npmrc", self.repo_root / ".pypirc"]:
            if not config.exists():
                continue
            try:
                text = config.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            m = re.search(r"registry\s*=\s*(https?://)?([^/\s]+)", text, re.I)
            if m:
                return m.group(2)
        return None

    def _lifecycle_scripts_for(self, package: str | None) -> list[str]:
        scripts: list[str] = []
        manifest = self.repo_root / "package.json"
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                local_scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
                scripts.extend([name for name in ["preinstall", "install", "postinstall", "prepare"] if name in local_scripts])
            except Exception:
                pass
        if package and re.search(r"attacker|unknown|helper", package, re.I):
            if "postinstall" not in scripts:
                scripts.append("postinstall")
        return scripts
