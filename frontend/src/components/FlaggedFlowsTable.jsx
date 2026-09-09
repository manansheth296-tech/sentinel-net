import { useState } from "react";
import { Network, ChevronRight } from "lucide-react";
import StageBadge from "./StageBadge";
import { severityColor } from "../lib/severity";

function RiskBar({ score }) {
  const c = severityColor(score);
  const pct = Math.round(score * 100);
  return (
    <div className="flex items-center gap-2 min-w-[110px]">
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: "var(--border)" }}>
        <div
          className={`h-full rounded-full transition-all duration-700 ${c.tailwindBar}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={`font-mono text-xs tabular-nums ${c.tailwindText}`}>{pct}%</span>
    </div>
  );
}

export default function FlaggedFlowsTable({ data }) {
  const { flagged_flows, predicted_stage, infiltration_timeline } = data;
  const [selected, setSelected] = useState(new Set());
  const latestWindow = infiltration_timeline[infiltration_timeline.length - 1]?.window_start ?? null;

  function toggleRow(idx) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  }

  function toggleAll() {
    setSelected(
      selected.size === flagged_flows.length
        ? new Set()
        : new Set(flagged_flows.map((_, i) => i))
    );
  }

  return (
    <section
      aria-labelledby="flagged-flows-heading"
      className="rounded-2xl border overflow-hidden transition-colors"
      style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-5 py-4 border-b"
        style={{ borderColor: "var(--border)" }}
      >
        <div>
          <h2 id="flagged-flows-heading" className="text-sm font-semibold text-primary">
            Flagged Flows
          </h2>
          <p className="text-xs text-muted">
            {flagged_flows.length} flow{flagged_flows.length !== 1 ? "s" : ""} detected
          </p>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm" role="grid">
          <thead>
            <tr className="border-b text-left" style={{ borderColor: "var(--border)" }}>
              <th className="px-5 py-3 w-10">
                <input
                  type="checkbox"
                  aria-label="Select all rows"
                  checked={selected.size === flagged_flows.length && flagged_flows.length > 0}
                  onChange={toggleAll}
                  className="h-3.5 w-3.5 rounded accent-violet-500"
                />
              </th>
              {["Flow", "MITRE Stage", "Risk Score", "Detected", "Action"].map((h) => (
                <th key={h} className="px-4 py-3 text-xs font-medium uppercase tracking-wider text-muted">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {flagged_flows.map((flow, idx) => {
              const isSelected = selected.has(idx);
              const isAlt = idx % 2 === 1;
              return (
                <tr
                  key={idx}
                  className="border-b transition-colors cursor-pointer hover:bg-violet-500/5"
                  style={{
                    borderColor: "var(--border)",
                    backgroundColor: isSelected
                      ? "rgba(139,92,246,0.08)"
                      : isAlt
                      ? "var(--panel-alt)"
                      : "transparent",
                  }}
                  onClick={() => toggleRow(idx)}
                >
                  <td className="px-5 py-3.5">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleRow(idx)}
                      onClick={(e) => e.stopPropagation()}
                      className="h-3.5 w-3.5 rounded accent-violet-500"
                      aria-label={`Select flow ${flow.src_ip} to ${flow.dst_ip}`}
                    />
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="flex items-center gap-2">
                      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-violet-500/10 border border-violet-500/20">
                        <Network className="h-3.5 w-3.5 text-violet-400" />
                      </div>
                      <div>
                        <p className="font-mono text-xs text-primary">{flow.src_ip}</p>
                        <p className="font-mono text-xs text-muted">→ {flow.dst_ip}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3.5"><StageBadge stage={predicted_stage} /></td>
                  <td className="px-4 py-3.5"><RiskBar score={flow.risk_score} /></td>
                  <td className="px-4 py-3.5">
                    <span className="font-mono text-xs text-muted">{latestWindow ?? "just now"}</span>
                  </td>
                  <td className="px-4 py-3.5">
                    <button
                      type="button"
                      aria-label={`Inspect flow ${flow.src_ip}`}
                      onClick={(e) => { e.stopPropagation(); console.log("[SentinelNet] Inspect:", flow); }}
                      className="flex h-7 w-7 items-center justify-center rounded-lg border text-muted hover:text-violet-400 hover:border-violet-500/50 transition-colors"
                      style={{ borderColor: "var(--border)" }}
                    >
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
