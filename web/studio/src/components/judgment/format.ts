import { displayLabel } from "../DecisionBadge";
import { actionLabel, reasonLabels, shortId } from "../displayText";
import type { JudgmentTraceViewModel, PolicyPredicateRow, Severity } from "../../types";

export function severityForDecision(decision: string): Severity {
  if (decision === "block" || decision === "quarantine") return "critical";
  if (decision.includes("sandbox") || decision.includes("approval")) return "warning";
  if (decision === "allow") return "normal";
  return "info";
}

export function valueText(value: unknown): string {
  if (value === undefined || value === null || value === "") return "无";
  if (Array.isArray(value)) return value.map(valueText).join("、");
  if (typeof value === "object") return JSON.stringify(value);
  return displayLabel(String(value));
}

export function ruleTitle(rule: Record<string, unknown>): string {
  const id = String(rule.rule_id || rule.id || "");
  if (id.includes("SECRET")) return `${id} · 密钥保护`;
  if (id.includes("EGRESS") || id.includes("NET")) return `${id} · 网络外传`;
  if (id.includes("CI")) return `${id} · CI/CD 发布边界`;
  if (id.includes("SC") || id.includes("PACKAGE") || id.includes("REGISTRY")) return `${id} · 供应链风险`;
  if (id.includes("SOURCE")) return `${id} · 低可信来源`;
  if (id.includes("REPO")) return `${id} · 仓库边界`;
  return id || "策略规则";
}

export function predicatePath(row: PolicyPredicateRow): string {
  const raw = String(row.path || "证据事实");
  const map: Record<string, string> = {
    "action.semantic_action": "动作类型",
    "action.risk": "动作风险",
    "source.trust_floor": "来源可信度",
    "source.has_untrusted": "是否含低可信来源",
    "asset.touched_type": "触碰资产类型",
    "asset.touched_path": "触碰文件路径",
    "contract.match": "任务边界匹配",
    "contract.forbidden_file_touch": "是否触碰禁止文件",
    "secret.event": "密钥风险事件",
    "package.source": "依赖来源",
    "mcp.capability": "MCP 能力",
    "sandbox.observation": "沙箱观察"
  };
  return map[raw] || displayLabel(raw);
}

export function oneLineAction(judgment: JudgmentTraceViewModel): string {
  return actionLabel(judgment.action_summary.semantic_action || judgment.action_id);
}

export function evidenceRefText(refs: unknown): string {
  if (!Array.isArray(refs) || !refs.length) return "无直接证据引用";
  return refs.map((ref) => shortId(String(ref))).join("、");
}

export function reasonText(judgment: JudgmentTraceViewModel): string {
  const labels = reasonLabels(judgment.reason_codes);
  return labels.length ? labels.join("、") : judgment.why_text || "当前判断没有额外原因码。";
}
