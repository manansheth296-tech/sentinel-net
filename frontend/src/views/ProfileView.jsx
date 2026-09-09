import { User, Clock, ArrowRight, BarChart2 } from "lucide-react";
import StageBadge from "../components/StageBadge";
import { severityColor } from "../lib/severity";
import { useApp } from "../context/AppContext";

function formatTime(iso) {
  try { return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
  catch { return iso; }
}
function formatDate(iso) {
  try { return new Date(iso).toLocaleDateString([], { month: "short", day: "numeric" }); }
  catch { return ""; }
}

export default function ProfileView() {
  const { state, dispatch } = useApp();
  const { analysisHistory } = state;

  function loadEntry(entry) {
    dispatch({ type: "SET_RESULT_FROM_HISTORY", payload: entry.result });
    dispatch({ type: "SET_VIEW", payload: "live-analysis" });
  }

  return (
    <div className="mx-auto max-w-2xl space-y-5">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-violet-600/20 border border-violet-500/30">
          <User className="h-5 w-5 text-violet-400" />
        </div>
        <div>
          <p className="text-sm font-semibold text-primary">Session Profile</p>
          <p className="text-xs text-muted">
            {analysisHistory.length} analysis run{analysisHistory.length !== 1 ? "s" : ""} this session
          </p>
        </div>
      </div>

      <div
        className="rounded-2xl border overflow-hidden transition-colors"
        style={{ backgroundColor: "var(--panel)", borderColor: "var(--border)" }}
      >
        <div
          className="flex items-center justify-between px-5 py-3 border-b"
          style={{ borderColor: "var(--border)" }}
        >
          <div className="flex items-center gap-2">
            <Clock className="h-3.5 w-3.5 text-muted" />
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">
              Analysis History
            </span>
          </div>
          <BarChart2 className="h-3.5 w-3.5 text-muted" />
        </div>

        {analysisHistory.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 py-16">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-violet-600/10 border border-violet-500/20">
              <Clock className="h-5 w-5 text-violet-400/50" />
            </div>
            <p className="text-sm text-muted">No analyses run yet this session</p>
          </div>
        ) : (
          <div className="divide-y" style={{ borderColor: "var(--border)" }}>
            {analysisHistory.map((entry) => {
              const c = severityColor(entry.peakProbability);
              return (
                <button
                  key={entry.id}
                  type="button"
                  onClick={() => loadEntry(entry)}
                  className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-violet-500/5 transition-colors group"
                >
                  <div className="shrink-0 text-right w-16">
                    <p className="font-mono text-xs text-primary">{formatTime(entry.timestamp)}</p>
                    <p className="font-mono text-[10px] text-muted">{formatDate(entry.timestamp)}</p>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-xs text-primary truncate">{entry.sourceLabel}</p>
                    <div className="mt-1"><StageBadge stage={entry.predicted_stage} /></div>
                  </div>
                  <div className="shrink-0 text-right">
                    <p className="font-mono text-sm font-bold" style={{ color: c.hex }}>
                      {Math.round(entry.peakProbability * 100)}%
                    </p>
                    <p className="text-[10px] text-muted">peak risk</p>
                  </div>
                  <ArrowRight className="h-3.5 w-3.5 text-muted group-hover:text-violet-400 transition-colors shrink-0" />
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
