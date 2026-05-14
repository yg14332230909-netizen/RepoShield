"""Registry of evidence facts that can safely drive RuleIndex retrieval."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FactKeySpec:
    path: str
    value_type: str
    cardinality: str
    index_strategy: str
    safety_role: str
    monotone_safe: bool
    ui_label: str
    description: str


FACT_KEY_REGISTRY: dict[str, FactKeySpec] = {
    "action.semantic_action": FactKeySpec("action.semantic_action", "enum", "medium", "exact", "action", True, "动作语义", "代理动作的标准化语义。"),
    "action.risk": FactKeySpec("action.risk", "enum", "low", "exact", "action", True, "动作风险", "动作解析阶段给出的风险等级。"),
    "action.high_risk": FactKeySpec("action.high_risk", "bool", "low", "boolean", "action", True, "高危动作", "动作是否属于高危能力。"),
    "action.network_capability": FactKeySpec("action.network_capability", "bool", "low", "boolean", "sink", True, "联网能力", "动作是否可能连接外部网络。"),
    "action.parser_confidence": FactKeySpec("action.parser_confidence", "number", "medium", "range_bucket", "observation", False, "解析置信度", "低置信副作用规则可用的数值事实。"),
    "source.trust_floor": FactKeySpec("source.trust_floor", "enum", "low", "exact", "authority", True, "来源可信度", "影响动作授权强弱的来源证据。"),
    "source.has_untrusted": FactKeySpec("source.has_untrusted", "bool", "low", "boolean", "taint", True, "存在低可信来源", "是否受到外部低可信文本影响。"),
    "asset.touched_type": FactKeySpec("asset.touched_type", "list", "medium", "list_each", "asset", True, "触碰资产类型", "动作触及的资产类别。"),
    "asset.repo_escape": FactKeySpec("asset.repo_escape", "bool", "low", "boolean", "asset", True, "仓库边界逃逸", "是否越过仓库边界。"),
    "asset.symlink_escape": FactKeySpec("asset.symlink_escape", "bool", "low", "boolean", "asset", True, "符号链接逃逸", "是否通过符号链接绕过边界。"),
    "contract.match": FactKeySpec("contract.match", "enum", "low", "exact", "contract", True, "任务边界匹配", "动作是否符合用户任务契约。"),
    "contract.forbidden_file_touch": FactKeySpec("contract.forbidden_file_touch", "bool", "low", "boolean", "contract", True, "触碰禁止文件", "动作是否触碰任务禁止文件。"),
    "package.source": FactKeySpec("package.source", "enum", "low", "exact", "sink", True, "依赖来源", "依赖来自 registry、git_url 或 tarball_url。"),
    "package.lifecycle_scripts": FactKeySpec("package.lifecycle_scripts", "bool", "low", "boolean", "sink", True, "生命周期脚本", "依赖是否存在安装脚本风险。"),
    "secret.event": FactKeySpec("secret.event", "enum", "medium", "exact", "taint", True, "密钥事件", "SecretSentry 产生的安全事件。"),
    "sandbox.risk_observed": FactKeySpec("sandbox.risk_observed", "list", "medium", "list_each", "observation", True, "沙箱风险观察", "沙箱预检观察到的风险。"),
    "mcp.capability": FactKeySpec("mcp.capability", "string", "medium", "exact", "sink", True, "MCP 能力", "MCP 工具暴露的能力。"),
    "memory.authorization": FactKeySpec("memory.authorization", "enum", "low", "exact", "authority", True, "记忆授权", "MemoryStore 授权或拒绝事件。"),
}


def fact_spec(path: str) -> FactKeySpec | None:
    return FACT_KEY_REGISTRY.get(path)
