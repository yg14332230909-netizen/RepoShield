import type { JudgmentTraceViewModel } from "../../types";
import { displayLabel } from "../DecisionBadge";
import { evidenceRefText, valueText } from "./format";

interface FactView {
  id: string;
  namespace: string;
  key: string;
  title: string;
  value: string;
  explanation: string;
  refs: string[];
  important: boolean;
  internal: boolean;
}

const groupMeta: Record<string, { label: string; subtitle: string }> = {
  source: { label: "来源可信度", subtitle: "这一步判断动作受到谁影响，外部 Issue/PR 评论是否可信。" },
  action: { label: "动作理解", subtitle: "这一步把代理想执行的命令翻译成安全系统能理解的动作。" },
  asset: { label: "资产影响", subtitle: "这一步判断动作碰到了哪些文件、配置或敏感资产。" },
  contract: { label: "任务边界", subtitle: "这一步判断动作是否还在用户真正授权的任务范围内。" },
  secret: { label: "密钥风险", subtitle: "这一步记录密钥读取、外传或凭据暴露风险。" },
  package: { label: "依赖来源", subtitle: "这一步判断依赖安装是否来自可疑 Git、tarball 或 registry。" },
  sandbox: { label: "沙箱观察", subtitle: "这一步展示隔离预检中观察到的文件、网络或进程行为。" },
  policy: { label: "系统内部状态", subtitle: "这些是策略引擎自用的辅助事实，默认折叠，通常不需要普通用户理解。" },
};

const factText: Record<string, { title: string; explain: (value: string) => string }> = {
  "source.trust_floor": { title: "来源可信等级", explain: (value) => value.includes("不可信") ? "低可信来源不能直接授权高风险工具动作。" : "来源可信度会影响后续策略的严格程度。" },
  "source.has_untrusted": { title: "是否包含不可信来源", explain: (value) => value === "是" ? "该动作受到外部低可信文本影响，需要更严格检查。" : "当前没有发现低可信来源影响。" },
  "action.semantic_action": { title: "动作类型", explain: () => "RepoShield 先把原始命令归类成标准动作，再进入策略判断。" },
  "action.risk": { title: "动作风险等级", explain: () => "风险等级越高，越容易触发沙箱、审批或阻断。" },
  "action.tool": { title: "调用工具", explain: () => "说明代理准备通过哪个工具执行这个动作。" },
  "action.side_effect": { title: "是否会产生副作用", explain: (value) => value === "是" ? "该动作可能改变仓库、环境或外部系统，不能只当作普通读取。" : "该动作暂未被识别为会修改外部状态。" },
  "action.parser_confidence": { title: "动作解析置信度", explain: () => "置信度表示系统对动作分类的把握程度。" },
  "action.high_risk": { title: "是否高危动作", explain: (value) => value === "是" ? "高危动作会触发更强的策略约束。" : "单看动作类型未被标成高危，但仍可能因资产或来源被阻断。" },
  "action.network_capability": { title: "是否具备联网能力", explain: (value) => value === "是" ? "联网能力会和密钥、低可信来源一起构成外传风险。" : "该动作本身没有被识别出直接联网能力。" },
  "action.risk_tag": { title: "风险标签", explain: () => "风险标签用于说明动作里包含的危险语义，例如密钥访问、网络外传或复合命令。" },
  "asset.touched_path": { title: "触碰文件路径", explain: () => "文件路径用于判断动作影响的是源码、配置、CI 还是密钥资产。" },
  "asset.touched_type": { title: "触碰资产类型", explain: (value) => value.includes("密钥") || value.includes("secret") ? "触碰密钥类资产会触发不可降级安全不变量。" : "资产类型决定策略要按普通文件还是敏感资产处理。" },
  "asset.touched_risk": { title: "资产风险等级", explain: () => "资产风险用于辅助判断是否需要阻断或沙箱。" },
  "asset.repo_escape": { title: "是否越过仓库边界", explain: (value) => value === "是" ? "越过仓库边界意味着动作可能访问项目外资源，风险很高。" : "未发现访问仓库边界之外的路径。" },
  "asset.symlink_escape": { title: "是否通过符号链接逃逸", explain: (value) => value === "是" ? "符号链接逃逸可能绕过文件边界限制。" : "未发现符号链接逃逸。" },
  "contract.match": { title: "是否符合任务边界", explain: (value) => value.includes("越界") ? "动作超出了用户授权的修复任务，因此不能直接执行。" : "任务边界用于区分正常工作和被外部诱导的危险动作。" },
  "contract.violation_reason": { title: "越界原因", explain: () => "这说明动作为什么不属于用户原始任务授权。" },
  "contract.forbidden_file_touch": { title: "是否触碰禁止文件", explain: (value) => value === "是" ? "触碰禁止文件是强风险信号，常见于密钥读取攻击。" : "未触碰任务合同中禁止访问的文件。" },
  "secret.event": { title: "密钥安全事件", explain: () => "密钥事件会直接参与不可降级安全不变量判断。" },
  "package.source": { title: "依赖来源", explain: () => "可疑依赖来源可能触发供应链防护策略。" },
  "sandbox.observation": { title: "沙箱观察结果", explain: () => "沙箱观察用于补强静态判断，说明预检时实际看到了什么。" },
};

export function FactMatrix({ judgment, activeFactId, onSelectFact }: { judgment: JudgmentTraceViewModel; activeFactId: string; onSelectFact: (factId: string, refs: string[]) => void }) {
  const facts = judgment.fact_nodes.map(toFactView);
  const publicFacts = facts.filter((fact) => !fact.internal);
  const internalFacts = facts.filter((fact) => fact.internal);
  const grouped = groupFacts(publicFacts);
  return (
    <section className="judgment-panel fact-matrix-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Evidence Facts</span>
        <h3>系统真正拿来判断的证据事实</h3>
        <p className="muted">这里不展示内部字段名优先，而是解释每条事实在安全判断里有什么用。点击事实会反向高亮它来自哪条证据。</p>
      </div>
      {[...grouped.entries()].map(([namespace, groupFacts]) => (
        <section className="fact-group" key={namespace}>
          <div className="fact-group-head">
            <div><b>{groupMeta[namespace]?.label || displayLabel(namespace)}</b><span>{groupMeta[namespace]?.subtitle || "这些事实会参与策略判断。"}</span></div>
            <small>{groupFacts.length} 条</small>
          </div>
          <div className="fact-card-grid">
            {groupFacts.map((fact) => (
              <button className={`fact-card ${fact.important ? "important" : ""} ${activeFactId === fact.id ? "active" : ""}`} key={fact.id} onClick={() => onSelectFact(fact.id, fact.refs)}>
                <span>{fact.title}</span>
                <b>{fact.value}</b>
                <p>{fact.explanation}</p>
                <small>证据：{evidenceRefText(fact.refs)}</small>
              </button>
            ))}
          </div>
        </section>
      ))}
      {internalFacts.length ? (
        <details className="internal-facts">
          <summary>查看系统内部状态事实（{internalFacts.length} 条）</summary>
          <div className="fact-card-grid">
            {internalFacts.map((fact) => (
              <button className={`fact-card internal ${activeFactId === fact.id ? "active" : ""}`} key={fact.id} onClick={() => onSelectFact(fact.id, fact.refs)}>
                <span>{fact.title}</span>
                <b>{fact.value}</b>
                <p>{fact.explanation}</p>
                <small>证据：{evidenceRefText(fact.refs)}</small>
              </button>
            ))}
          </div>
        </details>
      ) : null}
      {!judgment.fact_nodes.length ? <div className="empty-state">该动作无 PolicyFactSet。旧日志仍可展示原始策略结论，但无法复现完整判断链。</div> : null}
    </section>
  );
}

function groupFacts(facts: FactView[]): Map<string, FactView[]> {
  const order = ["source", "action", "asset", "contract", "secret", "package", "sandbox"];
  const grouped = new Map<string, FactView[]>();
  for (const ns of order) grouped.set(ns, []);
  for (const fact of facts) grouped.set(fact.namespace, [...(grouped.get(fact.namespace) || []), fact]);
  return new Map([...grouped.entries()].filter(([, items]) => items.length));
}

function toFactView(fact: Record<string, unknown>): FactView {
  const namespace = String(fact.namespace || "policy");
  const key = String(fact.key || "fact");
  const factKey = `${namespace}.${key}`;
  const id = String(fact.fact_id || fact.id || factKey);
  const refs = Array.isArray(fact.evidence_refs) ? fact.evidence_refs.map(String) : [];
  const value = readableValue(factKey, fact.value);
  const meta = factText[factKey] || { title: readableKey(key), explain: () => "这是策略引擎抽取出的辅助事实，会影响候选规则或条件判断。" };
  return {
    id,
    namespace,
    key,
    title: meta.title,
    value,
    explanation: meta.explain(value),
    refs,
    important: isImportantFact(factKey, value),
    internal: namespace === "policy" || key.includes("hash") || key.includes("version"),
  };
}

function readableValue(factKey: string, value: unknown): string {
  if (value === "<REDACTED>") return redactedMeaning(factKey);
  if (Array.isArray(value)) return value.map((item) => readableValue(factKey, item)).join("、");
  if (typeof value === "boolean") return value ? "是" : "否";
  if (value === null || value === undefined || value === "") return "无";
  if (typeof value === "object") return "结构化对象";
  return displayLabel(String(value));
}

function redactedMeaning(factKey: string): string {
  if (factKey === "source.trust_floor") return "不可信";
  if (factKey === "action.semantic_action") return "读取密钥文件";
  if (factKey === "action.risk") return "高危";
  if (factKey === "action.tool") return "命令行工具";
  if (factKey === "action.risk_tag") return "敏感风险标签";
  if (factKey === "asset.touched_path") return "敏感路径已隐藏";
  if (factKey === "asset.touched_type") return "密钥类资产";
  if (factKey === "asset.touched_risk") return "高敏感资产";
  if (factKey === "contract.match") return "越过任务边界";
  if (factKey === "contract.violation_reason") return "访问任务禁止内容";
  if (factKey === "secret.event") return "密钥读取或外传风险";
  return "已脱敏";
}

function readableKey(key: string): string {
  return displayLabel(key.replaceAll("_", " "));
}

function isImportantFact(factKey: string, value: string): boolean {
  return [
    "source.has_untrusted",
    "source.trust_floor",
    "asset.touched_type",
    "contract.match",
    "contract.forbidden_file_touch",
    "secret.event",
    "action.semantic_action",
  ].includes(factKey) || value.includes("密钥") || value.includes("越过") || value === "是";
}
