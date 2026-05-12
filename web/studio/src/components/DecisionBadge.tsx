import type { Severity } from "../types";

export function DecisionBadge({ label, severity = "info" }: { label: string; severity?: Severity }) {
  return <span className={`badge ${severity}`}>{label || "info"}</span>;
}
