import { FileText, AlertTriangle } from "lucide-react";
import StageBadge from "./StageBadge";
import { severityColor } from "../lib/severity";
import { useApp } from "../context/AppContext";
import { useCallback } from "react";

function buildNarrative(result) {
  const { infiltration_timeline, predicted_stage, top_features, flagged_flows } = result;
  const n = infiltration_timeline.length;
  const first = Math.round(infiltration_timeline[0].probability * 100);
  const peak = Math.round(Math.max(...infiltration_timeline.map((t) => t.probability)) * 100);
  const f0 = { ...top_features[0], pct: Math.round(top_features[0].importance * 100) };
  const f1raw = top_features[1] ?? { feature: "N/A", importance: 0 };
  const f1 = { ...f1raw, pct: Math.round(f1raw.importance * 100) };
  const flow0 = flagged_flows[0]
    ? { ...flagged_flows[0], pct: Math.round(flagged_flows[0].risk_score * 100) }
    : null;
  return { n, first, peak, predicted_stage, f0, f1, flowCount: flagged_flows.length, flow0 };
}

export default function FindingsReport({ result }) {
  const { dispatch } = useApp();
  const d = buildNarrative(result);
  const peakColor = severityColor(d.peak / 100);

  const goToLive = useCallback(
    () => dispatch({ type: "SET_VIEW", payload: "live-analysis" }),
    [dispatch]
  );

  return (
    <section aria-labelledby="findings-heading" className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-600/10 border border-violet-500/20">
          <FileText className="h-4 w-4 text-violet-400" />
        </div>
        <div>
          <h2 id="findings-heading" className="text-sm font-semibold text-primary">Analysis Findings</h2>
          <p className="text-xs text-muted">Auto-generated from inference results</p>
        </div>
      </div>

      {/* Critical alert */}
      {d.peak >= 70 && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/5 px-4 py-3">
          <AlertTriangle className="h-4 w-4 text-rose-400 mt-0.5 shrink-0" />
          <p className="text-sm text-rose-300">
            <strong>Critical threat level detected.</strong> Immediate investigation recommended.
          </p>
        </div>
      )}

      {/* Narrative */}
      <div
        className="rounded-2xl border p-6 space-y-4 transition-colors"
        style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
      >
        {/* Para 1 */}
        <p className="leading-relaxed text-primary text-sm">
          This session analyzed{" "}
          <span className="font-mono font-semibold text-violet-400">{d.n}</span>{" "}
          time windows of network traffic. Attack probability rose from{" "}
          <span className="font-mono font-semibold" style={{ color: severityColor(d.first / 100).hex }}>
            {d.first}%
          </span>{" "}
          to a peak of{" "}
          <span className="font-mono font-semibold" style={{ color: peakColor.hex }}>
            {d.peak}%
          </span>
          , currently assessed at the <StageBadge stage={d.predicted_stage} />{" "}
          stage of the MITRE ATT&CK lifecycle.
        </p>

        <div className="h-px" style={{ backgroundColor: "var(--border)" }} />

        {/* Para 2 */}
        <p className="leading-relaxed text-primary text-sm">
          The strongest indicators were{" "}
          <strong className="text-violet-400">{d.f0.feature}</strong>{" "}
          (<span className="font-mono text-violet-400">{d.f0.pct}%</span> importance) and{" "}
          <strong className="text-violet-400">{d.f1.feature}</strong>{" "}
          (<span className="font-mono text-violet-400">{d.f1.pct}%</span> importance).
          These patterns are consistent with{" "}
          <span className="font-semibold text-primary">{d.predicted_stage}</span> behavior.
        </p>

        <div className="h-px" style={{ backgroundColor: "var(--border)" }} />

        {/* Para 3 */}
        <p className="leading-relaxed text-primary text-sm">
          <span className="font-mono font-semibold" style={{ color: peakColor.hex }}>
            {d.flowCount}
          </span>{" "}
          flow{d.flowCount !== 1 ? "s were" : " was"} flagged as suspicious.
          {d.flow0 && (
            <> The highest-risk flow was{" "}
              <span className="font-mono font-semibold text-violet-400">{d.flow0.src_ip}</span>
              {" → "}
              <span className="font-mono font-semibold text-violet-400">{d.flow0.dst_ip}</span>{" "}
              at a{" "}
              <span className="font-mono font-semibold" style={{ color: severityColor(d.flow0.risk_score).hex }}>
                {d.flow0.pct}%
              </span>{" "}
              risk score.
            </>
          )}
        </p>

        <div className="h-px" style={{ backgroundColor: "var(--border)" }} />

        {/* Disclaimer */}
        <p className="text-xs text-muted italic leading-relaxed">
          These findings are probabilistic ML outputs — false positives and negatives are possible.
          View raw data on the{" "}
          <button onClick={goToLive} className="text-violet-400 hover:underline">
            Live Analysis
          </button>{" "}
          tab.
        </p>
      </div>

      {/* Feature attribution */}
      <div
        className="rounded-2xl border p-5 transition-colors"
        style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
      >
        <p className="text-xs font-semibold uppercase tracking-widest text-muted mb-4">
          Feature Attribution Breakdown
        </p>
        <div className="space-y-3">
          {result.top_features.map((f) => (
            <div key={f.feature} className="flex items-center gap-3">
              <span className="w-40 text-xs text-primary truncate" title={f.feature}>
                {f.feature}
              </span>
              <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ backgroundColor: "var(--border)" }}>
                <div
                  className="h-full rounded-full bg-violet-500 transition-all duration-700"
                  style={{ width: `${Math.round(f.importance * 100)}%` }}
                />
              </div>
              <span className="font-mono text-xs text-violet-400 w-10 text-right">
                {Math.round(f.importance * 100)}%
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
